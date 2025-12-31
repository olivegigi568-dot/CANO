//! Connection roundtrip tests for the high-level Connection API.

use std::sync::Arc;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, Connection, NetError, ServerConnectionConfig,
    ServerHandshakeConfig, TRANSPORT_TYPE_APP_MESSAGE,
};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing (copied from handshake_tests.rs)
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
// 3.1 Happy path: full handshake + app data both ways
// ============================================================================

#[test]
fn connection_handshake_and_app_data_roundtrip() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);
    let mut server = Connection::new_server(setup.server_cfg);

    // Verify initial state
    assert!(!client.is_established());
    assert!(!server.is_established());

    // Step 1: Client starts handshake
    let c1 = client.start_handshake().expect("client start_handshake should succeed");

    // Step 2: Server handles ClientInit and produces ServerAccept
    let s1 = server
        .handle_handshake_frame(&c1)
        .expect("server handle_handshake_frame should succeed")
        .expect("server should produce a reply");

    // Server should now be established
    assert!(server.is_established());

    // Step 3: Client handles ServerAccept
    let c2 = client
        .handle_handshake_frame(&s1)
        .expect("client handle_handshake_frame should succeed");

    // Client should not produce a reply
    assert!(c2.is_none());

    // Client should now be established
    assert!(client.is_established());

    // App data roundtrip: client → server
    let msg = b"hello from client";
    let frame = client.encrypt_app(msg).expect("client encrypt_app should succeed");
    let plain = server.decrypt_app(&frame).expect("server decrypt_app should succeed");
    assert_eq!(&plain[..], msg);

    // App data roundtrip: server → client
    let msg2 = b"hello from server";
    let frame2 = server.encrypt_app(msg2).expect("server encrypt_app should succeed");
    let plain2 = client.decrypt_app(&frame2).expect("client decrypt_app should succeed");
    assert_eq!(&plain2[..], msg2);
}

#[test]
fn connection_multiple_app_messages_both_directions() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);
    let mut server = Connection::new_server(setup.server_cfg);

    // Complete handshake
    let c1 = client.start_handshake().unwrap();
    let s1 = server.handle_handshake_frame(&c1).unwrap().unwrap();
    client.handle_handshake_frame(&s1).unwrap();

    // Send multiple messages client → server
    for i in 0..5 {
        let msg = format!("client message {}", i);
        let frame = client.encrypt_app(msg.as_bytes()).unwrap();
        let plain = server.decrypt_app(&frame).unwrap();
        assert_eq!(&plain[..], msg.as_bytes());
    }

    // Send multiple messages server → client
    for i in 0..5 {
        let msg = format!("server message {}", i);
        let frame = server.encrypt_app(msg.as_bytes()).unwrap();
        let plain = client.decrypt_app(&frame).unwrap();
        assert_eq!(&plain[..], msg.as_bytes());
    }

    // Interleaved messages
    for i in 0..3 {
        let c_msg = format!("client interleaved {}", i);
        let c_frame = client.encrypt_app(c_msg.as_bytes()).unwrap();

        let s_msg = format!("server interleaved {}", i);
        let s_frame = server.encrypt_app(s_msg.as_bytes()).unwrap();

        let c_plain = server.decrypt_app(&c_frame).unwrap();
        let s_plain = client.decrypt_app(&s_frame).unwrap();

        assert_eq!(&c_plain[..], c_msg.as_bytes());
        assert_eq!(&s_plain[..], s_msg.as_bytes());
    }
}

// ============================================================================
// 3.2 Misuse cases
// ============================================================================

#[test]
fn encrypt_app_before_established_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);

    // Try to encrypt before handshake is complete
    let result = client.encrypt_app(b"hello");
    assert!(matches!(
        result,
        Err(NetError::Protocol("encrypt_app called before handshake complete"))
    ));
}

#[test]
fn decrypt_app_before_established_returns_error() {
    let setup = create_test_setup();

    let mut server = Connection::new_server(setup.server_cfg);

    // Create a dummy frame bytes (msg_type + len + ciphertext)
    let mut frame_bytes = vec![TRANSPORT_TYPE_APP_MESSAGE];
    frame_bytes.extend_from_slice(&5u32.to_be_bytes());
    frame_bytes.extend_from_slice(b"hello");

    // Try to decrypt before handshake is complete
    let result = server.decrypt_app(&frame_bytes);
    assert!(matches!(
        result,
        Err(NetError::Protocol("decrypt_app called before handshake complete"))
    ));
}

#[test]
fn server_receives_wrong_handshake_type_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg.clone());
    let mut server = Connection::new_server(setup.server_cfg);

    // Client starts handshake
    let _ = client.start_handshake().unwrap();

    // Create a fake ServerAccept packet (wrong type for server to receive)
    let fake_packet = cano_net::HandshakePacket {
        msg_type: cano_net::HANDSHAKE_TYPE_SERVER_ACCEPT,
        payload: vec![0u8; 100],
    };
    let fake_bytes = fake_packet.encode();

    // Server should reject this
    let result = server.handle_handshake_frame(&fake_bytes);
    assert!(matches!(
        result,
        Err(NetError::Protocol("server expected ClientInit"))
    ));
}

#[test]
fn client_receives_wrong_handshake_type_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);
    let mut server = Connection::new_server(setup.server_cfg);

    // Client starts handshake
    let c1 = client.start_handshake().unwrap();

    // Server processes ClientInit normally
    let _ = server.handle_handshake_frame(&c1).unwrap().unwrap();

    // Create a fake ClientInit packet (wrong type for client to receive)
    let fake_packet = cano_net::HandshakePacket {
        msg_type: cano_net::HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0u8; 100],
    };
    let fake_bytes = fake_packet.encode();

    // Client should reject this
    let result = client.handle_handshake_frame(&fake_bytes);
    assert!(matches!(
        result,
        Err(NetError::Protocol("client expected ServerAccept"))
    ));
}

#[test]
fn decrypt_wrong_transport_frame_type_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);
    let mut server = Connection::new_server(setup.server_cfg);

    // Complete handshake
    let c1 = client.start_handshake().unwrap();
    let s1 = server.handle_handshake_frame(&c1).unwrap().unwrap();
    client.handle_handshake_frame(&s1).unwrap();

    // Create a frame with wrong msg_type (0xFF instead of TRANSPORT_TYPE_APP_MESSAGE)
    let mut wrong_frame_bytes = vec![0xFF]; // Wrong msg_type
    wrong_frame_bytes.extend_from_slice(&5u32.to_be_bytes());
    wrong_frame_bytes.extend_from_slice(b"hello");

    // Client should reject this
    let result = client.decrypt_app(&wrong_frame_bytes);
    assert!(matches!(
        result,
        Err(NetError::Protocol("unexpected transport frame type"))
    ));
}

#[test]
fn start_handshake_on_server_returns_error() {
    let setup = create_test_setup();

    let mut server = Connection::new_server(setup.server_cfg);

    // Server should not be able to start handshake
    let result = server.start_handshake();
    assert!(matches!(
        result,
        Err(NetError::Protocol("start_handshake called in invalid state"))
    ));
}

#[test]
fn handle_handshake_frame_after_established_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg);
    let mut server = Connection::new_server(setup.server_cfg);

    // Complete handshake
    let c1 = client.start_handshake().unwrap();
    let s1 = server.handle_handshake_frame(&c1).unwrap().unwrap();
    client.handle_handshake_frame(&s1).unwrap();

    // Try to handle another handshake frame after established
    let result = client.handle_handshake_frame(&s1);
    assert!(matches!(
        result,
        Err(NetError::Protocol("handle_handshake_frame called in invalid state"))
    ));
}

#[test]
fn client_handle_handshake_without_start_returns_error() {
    let setup = create_test_setup();

    let mut client = Connection::new_client(setup.client_cfg.clone());
    let mut server = Connection::new_server(setup.server_cfg.clone());

    // Create another client to get a valid ServerAccept
    let mut client2 = Connection::new_client(setup.client_cfg);
    let c1 = client2.start_handshake().unwrap();
    let s1 = server.handle_handshake_frame(&c1).unwrap().unwrap();

    // Try to handle ServerAccept without calling start_handshake first
    let result = client.handle_handshake_frame(&s1);
    assert!(matches!(
        result,
        Err(NetError::Protocol("client_init not set; call start_handshake first"))
    ));
}