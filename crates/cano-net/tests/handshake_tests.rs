//! Handshake integration tests for the KEMTLS-PDK engine.

use std::sync::Arc;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientHandshake, ClientHandshakeConfig, ServerHandshake, ServerHandshakeConfig,
};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
///
/// - encaps(pk) → (ct = pk || b"ct-pad", ss = pk || b"ss-pad")
/// - decaps(sk, ct) → ss derived from ct (first bytes of ct which were pk)
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
        // ct = pk || "ct-pad" (truncated/padded to ciphertext_len)
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        // ss = pk || "ss-pad" (truncated/padded to shared_secret_len)
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Extract the pk from ct (first 32 bytes), then derive ss the same way encaps does
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
        // Always succeed for testing
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
/// This is a copy from net_session_tests.rs for standalone use.
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
        // Simple XOR with first byte of key, then append tag
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        // Tag is just XOR of all ciphertext bytes
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

/// Create a test crypto provider with dummy KEM, AEAD, and signature suites.
fn make_test_provider(kem_suite_id: u8, aead_suite_id: u8, sig_suite_id: u8) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

/// Create a synthetic NetworkDelegationCert for testing.
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
        sig_bytes: vec![0u8; 64], // Dummy signature
    }
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn handshake_roundtrip_succeeds() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    // Create test provider
    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    // Create validator identity
    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    // Server's KEM keypair (dummy: pk and sk can be arbitrary for DummyKem)
    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    // Create delegation cert
    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    // Encode cert to bytes
    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    // Root network pk (for signature verification - dummy just accepts)
    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client config
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    // Server config
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    // Client random
    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    // Server random
    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    // Create handshake state machines
    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Step 1: Client generates ClientInit
    let client_init = client
        .start(validator_id, &server_kem_pk)
        .expect("client start should succeed");

    assert_eq!(client_init.version, 1);
    assert_eq!(client_init.kem_suite_id, kem_suite_id);
    assert_eq!(client_init.aead_suite_id, aead_suite_id);
    assert_eq!(client_init.client_random, client_random);
    assert_eq!(client_init.validator_id, validator_id);

    // Step 2: Server handles ClientInit, produces ServerAccept
    let (server_accept, server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("server handle_client_init should succeed");

    assert_eq!(server_accept.version, 1);
    assert_eq!(server_accept.kem_suite_id, kem_suite_id);
    assert_eq!(server_accept.aead_suite_id, aead_suite_id);
    assert_eq!(server_accept.server_random, server_random);
    assert_eq!(server_accept.client_random, client_random);

    // Step 3: Client handles ServerAccept, produces HandshakeResult
    let client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("client handle_server_accept should succeed");

    // Verify both sides agree on metadata
    assert_eq!(client_result.kem_suite_id, server_result.kem_suite_id);
    assert_eq!(client_result.aead_suite_id, server_result.aead_suite_id);
    assert_eq!(client_result.peer_validator_id, validator_id);
    assert_eq!(server_result.peer_validator_id, validator_id);
}

#[test]
fn handshake_aead_session_works() {
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

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Complete handshake
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    let (server_accept, mut server_result) = server.handle_client_init(&*provider, &client_init).unwrap();
    let mut client_result = client.handle_server_accept(&*provider, &client_init, &server_accept).unwrap();

    // Test AEAD: client sends message to server (c2s direction)
    let aad = b"CANO:test";
    let plaintext = b"Hello from client!";

    let ciphertext = client_result
        .session
        .c2s
        .seal(aad, plaintext)
        .expect("client c2s seal should succeed");

    let decrypted = server_result
        .session
        .c2s
        .open(aad, &ciphertext)
        .expect("server c2s open should succeed");

    assert_eq!(&decrypted[..], plaintext);

    // Test AEAD: server sends message to client (s2c direction)
    let plaintext_s2c = b"Hello from server!";

    let ciphertext_s2c = server_result
        .session
        .s2c
        .seal(aad, plaintext_s2c)
        .expect("server s2c seal should succeed");

    let decrypted_s2c = client_result
        .session
        .s2c
        .open(aad, &ciphertext_s2c)
        .expect("client s2c open should succeed");

    assert_eq!(&decrypted_s2c[..], plaintext_s2c);
}

#[test]
fn handshake_suite_mismatch_fails() {
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

    // Client requests a different KEM suite
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id: 99, // Different suite!
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    // Server supports the original suite
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let _server = ServerHandshake::new(server_cfg, server_random);

    // Client start will fail because crypto provider doesn't have suite 99
    let result = client.start(validator_id, &server_kem_pk);
    assert!(result.is_err());
}

#[test]
fn handshake_server_rejects_wrong_kem_suite() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;
    let wrong_kem_suite_id: u8 = 99;

    // Provider only has the "wrong" KEM suite for client, but server expects the original
    let client_provider = Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem::new(wrong_kem_suite_id)))
            .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
            .with_signature_suite(Arc::new(DummySig::new(sig_suite_id))),
    );

    let server_provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

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

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id: wrong_kem_suite_id,
        aead_suite_id,
        crypto: client_provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: server_provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client can start (it has suite 99)
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.kem_suite_id, wrong_kem_suite_id);

    // Server should reject because suite doesn't match
    let result = server.handle_client_init(&*server_provider, &client_init);
    assert!(result.is_err());
}

#[test]
fn handshake_validator_id_mismatch_fails() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    // Client expects validator_id_a
    let mut validator_id_a = [0u8; 32];
    validator_id_a[0..5].copy_from_slice(b"val-a");

    // Server cert has validator_id_b
    let mut validator_id_b = [0u8; 32];
    validator_id_b[0..5].copy_from_slice(b"val-b");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    // Cert has validator_id_b
    let cert = make_test_delegation_cert(
        validator_id_b,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client expects to talk to validator_id_a
    let client_init = client.start(validator_id_a, &server_kem_pk).unwrap();

    // Server processes the request (it doesn't check validator_id match)
    let (server_accept, _) = server.handle_client_init(&*provider, &client_init).unwrap();

    // Client should fail because cert's validator_id doesn't match what was expected
    let result = client.handle_server_accept(&*provider, &client_init, &server_accept);
    assert!(result.is_err());
}