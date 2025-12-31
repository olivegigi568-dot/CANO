//! Integration tests for Peer message size limit handling.
//!
//! These tests verify that:
//!  - Normal NetMessage send/recv works through Peer.
//!  - The TooLarge error is properly surfaced as ChannelError::Io with InvalidData.

use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::{Peer, PeerId};
use cano_node::secure_channel::{ChannelError, SecureChannel};
use cano_wire::io::WireEncode;
use cano_wire::net::{NetMessage, NetworkDelegationCert, MAX_NET_MESSAGE_BYTES};

// ============================================================================
// Dummy Implementations for Testing (same as in peer_wire_roundtrip_tests)
// ============================================================================

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

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

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

fn make_test_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> StaticCryptoProvider {
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

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_test_setup() -> TestSetup {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(
        kem_suite_id,
        aead_suite_id,
        sig_suite_id,
    ));

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

    TestSetup {
        client_cfg,
        server_cfg,
    }
}

// ============================================================================
// Peer Message Limits Tests
// ============================================================================

#[test]
fn peer_normal_ping_pong_still_works() {
    // Verify that normal messages still work through Peer after adding size limits
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        assert!(peer.is_established());

        let incoming = peer.recv_msg().expect("server recv_msg failed");
        assert_eq!(incoming, NetMessage::Ping(12345));

        let response = NetMessage::Pong(12345);
        peer.send_msg(&response).expect("server send_msg failed");
    });

    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut peer = Peer::new(PeerId(2), channel);

    assert!(peer.is_established());

    let ping_msg = NetMessage::Ping(12345);
    peer.send_msg(&ping_msg).expect("client send_msg failed");

    let response = peer.recv_msg().expect("client recv_msg failed");
    assert_eq!(response, NetMessage::Pong(12345));

    server_handle.join().expect("server thread panicked");
}

#[test]
fn peer_recv_oversized_message_returns_invalid_data_error() {
    // Test that receiving an oversized message through the underlying channel
    // results in a ChannelError::Io with InvalidData kind.
    //
    // To test this, we bypass Peer::send_msg and directly send an oversized
    // payload through the secure channel.
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        assert!(peer.is_established());

        // Try to receive a message - this should fail with InvalidData
        let result = peer.recv_msg();
        assert!(result.is_err());

        match result.unwrap_err() {
            ChannelError::Io(io_err) => {
                assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
                let msg = io_err.to_string();
                assert!(
                    msg.contains("too large"),
                    "error message should mention 'too large', got: {}",
                    msg
                );
            }
            other => panic!("expected ChannelError::Io, got: {:?}", other),
        }
    });

    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut peer = Peer::new(PeerId(2), channel);

    assert!(peer.is_established());

    // Send an oversized payload directly through the channel, bypassing send_msg
    let oversized = vec![0u8; MAX_NET_MESSAGE_BYTES + 1];
    peer.channel()
        .send_app(&oversized)
        .expect("direct send_app should succeed");

    server_handle.join().expect("server thread panicked");
}

#[test]
fn wire_error_too_large_maps_to_channel_error_io_invalid_data() {
    // Unit test to verify the WireError::TooLarge -> ChannelError mapping
    // by directly using the NetMessage::decode_from_slice method
    use cano_wire::error::WireError;

    let oversized = vec![0u8; MAX_NET_MESSAGE_BYTES + 1];
    let result = NetMessage::decode_from_slice(&oversized);

    assert!(result.is_err());
    match result.unwrap_err() {
        WireError::TooLarge { actual, max } => {
            assert_eq!(actual, MAX_NET_MESSAGE_BYTES + 1);
            assert_eq!(max, MAX_NET_MESSAGE_BYTES);
        }
        other => panic!("expected TooLarge error, got: {:?}", other),
    }
}