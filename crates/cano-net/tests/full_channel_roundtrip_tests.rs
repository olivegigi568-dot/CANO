//! Full-stack integration tests for KEMTLS handshake and application data over framed I/O.
//!
//! These tests exercise the entire stack together:
//! - `Connection` (handshake + session)
//! - `HandshakePacket`
//! - `TransportFrame`
//! - `framed_io` helpers
//! - In-memory `DuplexSide` streams (implementing both `Read` and `Write`)

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::rc::Rc;
use std::sync::Arc;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    read_handshake_packet, read_transport_frame, write_handshake_packet, write_transport_frame,
    ClientConnectionConfig, ClientHandshakeConfig, Connection, HandshakePacket,
    ServerConnectionConfig, ServerHandshakeConfig, TransportFrame,
};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// In-memory duplex stream abstraction
// ============================================================================

/// A single endpoint's buffer.
struct Endpoint {
    inbox: VecDeque<u8>,
}

impl Endpoint {
    fn new() -> Self {
        Self {
            inbox: VecDeque::new(),
        }
    }
}

/// Shared duplex state holding two endpoints.
struct Duplex {
    a: Endpoint,
    b: Endpoint,
}

/// Identifies which side of the duplex we are.
#[derive(Copy, Clone)]
enum Side {
    A,
    B,
}

/// A handle to one side of the duplex stream.
/// Implements both `Read` and `Write`:
/// - Reading from side A reads from A's inbox (data written by B).
/// - Writing from side A writes to B's inbox.
struct DuplexSide {
    inner: Rc<RefCell<Duplex>>,
    side: Side,
}

impl DuplexSide {
    /// Create a new duplex pair. Returns (side_a, side_b).
    fn new_pair() -> (DuplexSide, DuplexSide) {
        let duplex = Duplex {
            a: Endpoint::new(),
            b: Endpoint::new(),
        };
        let shared = Rc::new(RefCell::new(duplex));
        (
            DuplexSide {
                inner: shared.clone(),
                side: Side::A,
            },
            DuplexSide {
                inner: shared,
                side: Side::B,
            },
        )
    }
}

impl Read for DuplexSide {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut d = self.inner.borrow_mut();
        let inbox = match self.side {
            Side::A => &mut d.a.inbox,
            Side::B => &mut d.b.inbox,
        };

        let mut n = 0;
        while n < buf.len() {
            match inbox.pop_front() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => break,
            }
        }

        // Return 0 if no data available (simulates non-blocking with no data)
        Ok(n)
    }
}

impl Write for DuplexSide {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut d = self.inner.borrow_mut();
        // Writing from A goes to B's inbox, and vice versa
        let outbox = match self.side {
            Side::A => &mut d.b.inbox,
            Side::B => &mut d.a.inbox,
        };
        for &b in buf {
            outbox.push_back(b);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// ChunkedReader for simulating fragmented reads
// ============================================================================

/// A wrapper that limits each read to at most `max_chunk` bytes.
/// This simulates fragmented reads from slow or chunked streams.
struct ChunkedReader<R> {
    inner: R,
    max_chunk: usize,
}

impl<R> ChunkedReader<R> {
    fn new(inner: R, max_chunk: usize) -> Self {
        ChunkedReader { inner, max_chunk }
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf.len().min(self.max_chunk);
        self.inner.read(&mut buf[..limit])
    }
}

// ============================================================================
// Dummy crypto implementations for testing (same as connection_roundtrip_tests)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(
        &self,
        _pk: &[u8],
        _msg_digest: &[u8; 32],
        _sig: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let (ciphertext, tag_slice) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
        let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        if tag_slice[0] != expected_tag {
            return Err(CryptoError::InvalidCiphertext);
        }
        let xor_byte = key.first().copied().unwrap_or(0);
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
        Ok(plaintext)
    }
}

fn make_test_provider(kem_suite_id: u8, aead_suite_id: u8, sig_suite_id: u8) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

// ============================================================================
// Helper to create test client and server configurations
// ============================================================================

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_test_setup() -> TestSetup {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    TestSetup { client_cfg, server_cfg }
}

// ============================================================================
// 1.2 Full happy-path KEMTLS + app data roundtrip
// ============================================================================

#[test]
fn full_handshake_and_app_roundtrip_over_framed_io() {
    // 1. Build dummy crypto provider + client/server handshake configs
    let setup = create_test_setup();

    let mut client_conn = Connection::new_client(setup.client_cfg);
    let mut server_conn = Connection::new_server(setup.server_cfg);

    // 2. Create duplex channels for each direction
    let (mut client_side, mut server_side) = DuplexSide::new_pair();

    // 3. Client starts handshake, writes packet via framed_io
    let client_first = client_conn.start_handshake().expect("client start");
    {
        let packet = HandshakePacket::decode(&client_first).unwrap();
        write_handshake_packet(&mut client_side, &packet).unwrap();
    }

    // 4. Server reads handshake packet from stream, passes to Connection
    let server_pkt = read_handshake_packet(&mut server_side).expect("server read");
    let server_reply_bytes_opt = server_conn
        .handle_handshake_frame(&server_pkt.encode())
        .expect("server handle");
    assert!(server_reply_bytes_opt.is_some());
    let server_reply_bytes = server_reply_bytes_opt.unwrap();

    // 5. Server sends reply via framed_io, client reads it
    {
        let pkt = HandshakePacket::decode(&server_reply_bytes).unwrap();
        write_handshake_packet(&mut server_side, &pkt).unwrap();
    }

    let client_pkt = read_handshake_packet(&mut client_side).expect("client read");
    let client_reply = client_conn
        .handle_handshake_frame(&client_pkt.encode())
        .expect("client handle");
    assert!(client_reply.is_none());

    assert!(client_conn.is_established());
    assert!(server_conn.is_established());

    // 6. App data in both directions using Connection + framed_io
    let msg_c2s = b"hello from client over cano";
    let msg_s2c = b"greetings from server over cano";

    // client → server
    let c_frame_bytes = client_conn.encrypt_app(msg_c2s).unwrap();
    {
        let frame = TransportFrame::decode(&c_frame_bytes).unwrap();
        write_transport_frame(&mut client_side, &frame).unwrap();
    }
    let s_frame = read_transport_frame(&mut server_side).unwrap();
    let s_plain = server_conn.decrypt_app(&s_frame.encode().unwrap()).unwrap();
    assert_eq!(s_plain, msg_c2s);

    // server → client
    let s_frame_bytes = server_conn.encrypt_app(msg_s2c).unwrap();
    {
        let frame = TransportFrame::decode(&s_frame_bytes).unwrap();
        write_transport_frame(&mut server_side, &frame).unwrap();
    }
    let c_frame = read_transport_frame(&mut client_side).unwrap();
    let c_plain = client_conn.decrypt_app(&c_frame.encode().unwrap()).unwrap();
    assert_eq!(c_plain, msg_s2c);
}

// ============================================================================
// 1.3 Multiple messages / fragmentation
// ============================================================================

#[test]
fn multiple_app_messages_sequential_over_framed_io() {
    // Build connections and complete handshake
    let setup = create_test_setup();

    let mut client_conn = Connection::new_client(setup.client_cfg);
    let mut server_conn = Connection::new_server(setup.server_cfg);

    let (mut client_side, mut server_side) = DuplexSide::new_pair();

    // Handshake
    let client_first = client_conn.start_handshake().unwrap();
    {
        let packet = HandshakePacket::decode(&client_first).unwrap();
        write_handshake_packet(&mut client_side, &packet).unwrap();
    }

    let server_pkt = read_handshake_packet(&mut server_side).unwrap();
    let server_reply = server_conn
        .handle_handshake_frame(&server_pkt.encode())
        .unwrap()
        .unwrap();
    {
        let pkt = HandshakePacket::decode(&server_reply).unwrap();
        write_handshake_packet(&mut server_side, &pkt).unwrap();
    }

    let client_pkt = read_handshake_packet(&mut client_side).unwrap();
    client_conn
        .handle_handshake_frame(&client_pkt.encode())
        .unwrap();

    assert!(client_conn.is_established());
    assert!(server_conn.is_established());

    // Send multiple messages client → server with the same DuplexSides
    for i in 0..10 {
        let msg = format!("client message #{}", i);
        let frame_bytes = client_conn.encrypt_app(msg.as_bytes()).unwrap();
        let frame = TransportFrame::decode(&frame_bytes).unwrap();
        write_transport_frame(&mut client_side, &frame).unwrap();

        let recv_frame = read_transport_frame(&mut server_side).unwrap();
        let plaintext = server_conn.decrypt_app(&recv_frame.encode().unwrap()).unwrap();
        assert_eq!(plaintext, msg.as_bytes());
    }

    // Send multiple messages server → client
    for i in 0..10 {
        let msg = format!("server message #{}", i);
        let frame_bytes = server_conn.encrypt_app(msg.as_bytes()).unwrap();
        let frame = TransportFrame::decode(&frame_bytes).unwrap();
        write_transport_frame(&mut server_side, &frame).unwrap();

        let recv_frame = read_transport_frame(&mut client_side).unwrap();
        let plaintext = client_conn.decrypt_app(&recv_frame.encode().unwrap()).unwrap();
        assert_eq!(plaintext, msg.as_bytes());
    }

    // Interleaved messages: both directions simultaneously
    for i in 0..5 {
        // Client sends
        let c_msg = format!("client interleaved #{}", i);
        let c_frame_bytes = client_conn.encrypt_app(c_msg.as_bytes()).unwrap();
        let c_frame = TransportFrame::decode(&c_frame_bytes).unwrap();
        write_transport_frame(&mut client_side, &c_frame).unwrap();

        // Server sends
        let s_msg = format!("server interleaved #{}", i);
        let s_frame_bytes = server_conn.encrypt_app(s_msg.as_bytes()).unwrap();
        let s_frame = TransportFrame::decode(&s_frame_bytes).unwrap();
        write_transport_frame(&mut server_side, &s_frame).unwrap();

        // Server receives client's message
        let recv_c_frame = read_transport_frame(&mut server_side).unwrap();
        let c_plaintext = server_conn
            .decrypt_app(&recv_c_frame.encode().unwrap())
            .unwrap();
        assert_eq!(c_plaintext, c_msg.as_bytes());

        // Client receives server's message
        let recv_s_frame = read_transport_frame(&mut client_side).unwrap();
        let s_plaintext = client_conn
            .decrypt_app(&recv_s_frame.encode().unwrap())
            .unwrap();
        assert_eq!(s_plaintext, s_msg.as_bytes());
    }
}

#[test]
fn app_data_roundtrip_with_fragmented_reads() {
    // Build connections and complete handshake
    let setup = create_test_setup();

    let mut client_conn = Connection::new_client(setup.client_cfg);
    let mut server_conn = Connection::new_server(setup.server_cfg);

    let (mut client_side, mut server_side) = DuplexSide::new_pair();

    // Handshake (same as above)
    let client_first = client_conn.start_handshake().unwrap();
    {
        let packet = HandshakePacket::decode(&client_first).unwrap();
        write_handshake_packet(&mut client_side, &packet).unwrap();
    }

    let server_pkt = read_handshake_packet(&mut server_side).unwrap();
    let server_reply = server_conn
        .handle_handshake_frame(&server_pkt.encode())
        .unwrap()
        .unwrap();
    {
        let pkt = HandshakePacket::decode(&server_reply).unwrap();
        write_handshake_packet(&mut server_side, &pkt).unwrap();
    }

    let client_pkt = read_handshake_packet(&mut client_side).unwrap();
    client_conn
        .handle_handshake_frame(&client_pkt.encode())
        .unwrap();

    assert!(client_conn.is_established());
    assert!(server_conn.is_established());

    // Send several messages client → server
    // Each message is written to the stream in one shot
    // but we'll read them with a ChunkedReader to simulate fragmentation
    let messages = vec![
        b"short".to_vec(),
        b"a medium-length message for testing".to_vec(),
        (0..200).map(|i| (i % 256) as u8).collect::<Vec<u8>>(), // longer message
    ];

    for msg in &messages {
        let frame_bytes = client_conn.encrypt_app(msg).unwrap();
        let frame = TransportFrame::decode(&frame_bytes).unwrap();
        write_transport_frame(&mut client_side, &frame).unwrap();
    }

    // Now read them back using ChunkedReader (byte-by-byte)
    let mut chunked_server_side = ChunkedReader::new(server_side, 1);
    for expected in &messages {
        let recv_frame = read_transport_frame(&mut chunked_server_side).unwrap();
        let plaintext = server_conn
            .decrypt_app(&recv_frame.encode().unwrap())
            .unwrap();
        assert_eq!(&plaintext, expected);
    }
}

#[test]
fn handshake_with_fragmented_reads() {
    // Test that the handshake also works with fragmented reads
    let setup = create_test_setup();

    let mut client_conn = Connection::new_client(setup.client_cfg);
    let mut server_conn = Connection::new_server(setup.server_cfg);

    let (mut client_side, mut server_side) = DuplexSide::new_pair();

    // Client starts handshake
    let client_first = client_conn.start_handshake().unwrap();
    {
        let packet = HandshakePacket::decode(&client_first).unwrap();
        write_handshake_packet(&mut client_side, &packet).unwrap();
    }

    // Server reads with chunked reader (2 bytes at a time)
    {
        let mut chunked = ChunkedReader::new(&mut server_side, 2);
        let server_pkt = read_handshake_packet(&mut chunked).unwrap();
        let server_reply = server_conn
            .handle_handshake_frame(&server_pkt.encode())
            .unwrap()
            .unwrap();
        let pkt = HandshakePacket::decode(&server_reply).unwrap();
        write_handshake_packet(&mut server_side, &pkt).unwrap();
    }

    // Client reads with chunked reader (1 byte at a time)
    {
        let mut chunked = ChunkedReader::new(&mut client_side, 1);
        let client_pkt = read_handshake_packet(&mut chunked).unwrap();
        let reply = client_conn.handle_handshake_frame(&client_pkt.encode()).unwrap();
        assert!(reply.is_none());
    }

    assert!(client_conn.is_established());
    assert!(server_conn.is_established());

    // Verify app data still works after fragmented handshake
    let msg = b"test after fragmented handshake";
    let frame_bytes = client_conn.encrypt_app(msg).unwrap();
    let frame = TransportFrame::decode(&frame_bytes).unwrap();
    write_transport_frame(&mut client_side, &frame).unwrap();

    let recv_frame = read_transport_frame(&mut server_side).unwrap();
    let plaintext = server_conn.decrypt_app(&recv_frame.encode().unwrap()).unwrap();
    assert_eq!(plaintext, msg);
}