//! Integration tests for validator config wiring.
//!
//! These tests verify that:
//! - `build_net_config_and_id_map_for_tests` assigns PeerIds deterministically
//! - The wiring between NetServiceConfig and PeerValidatorMap is consistent
//! - ConsensusNode can use the identity map to correctly map peers to validators

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_consensus::{ConsensusNetwork, ConsensusNetworkEvent, ValidatorId};
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::consensus_net::ConsensusNetAdapter;
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_node::validator_config::{
    build_net_config_and_id_map_for_tests, LocalValidatorConfig, NodeValidatorConfig,
    RemoteValidatorConfig,
};
use cano_node::{ConsensusNode, NetService};
use cano_wire::consensus::Vote;
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (copied from consensus_node_smoke_tests.rs to keep tests self-contained)
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

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
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

/// Create a dummy Vote with the specified validator_index for testing.
fn make_dummy_vote_with_validator_index(validator_index: u16) -> Vote {
    let mut block_id = [0u8; 32];
    block_id[0..8].copy_from_slice(b"block-id");

    Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0, // Prevote
        block_id,
        validator_index,
        reserved: 0,
        signature: vec![0xAA; 64], // Dummy signature
    }
}

// ============================================================================
// Validator Config Wiring Tests
// ============================================================================

/// Test that `build_net_config_and_id_map_for_tests` assigns PeerIds deterministically.
///
/// This test:
/// 1. Creates a `NodeValidatorConfig` with:
///    - local.validator_id = ValidatorId(1)
///    - 3 remotes with ids 2, 3, 4 and distinct SocketAddrs
/// 2. Calls `build_net_config_and_id_map_for_tests(...)`
/// 3. Asserts:
///    - `NetServiceConfig.outbound_peers.len() == 3`
///    - The first remote in `cfg.remotes` got `PeerId(1)`, second `PeerId(2)`, etc.
///    - `PeerValidatorMap` maps `PeerId(1)` → `ValidatorId(2)`, etc.
#[test]
fn build_net_config_and_id_map_assigns_peer_ids_deterministically() {
    let setup = create_test_setup();

    let validator_config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
            consensus_pk: b"pk-1".to_vec(),
        },
        remotes: vec![
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(2),
                addr: "127.0.0.1:9001".parse().unwrap(),
                consensus_pk: b"pk-2".to_vec(),
            },
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(3),
                addr: "127.0.0.1:9002".parse().unwrap(),
                consensus_pk: b"pk-3".to_vec(),
            },
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(4),
                addr: "127.0.0.1:9003".parse().unwrap(),
                consensus_pk: b"pk-4".to_vec(),
            },
        ],
    };

    let (net_cfg, id_map) = build_net_config_and_id_map_for_tests(
        &validator_config,
        setup.client_cfg,
        setup.server_cfg,
        Duration::from_secs(5),
        Duration::from_secs(30),
        100,
    );

    // Check NetServiceConfig
    assert_eq!(net_cfg.outbound_peers.len(), 3);
    assert_eq!(
        net_cfg.listen_addr.port(),
        9000,
        "listen_addr should match local config"
    );

    // Check PeerId assignments in outbound_peers
    assert_eq!(
        net_cfg.outbound_peers[0].0,
        PeerId(1),
        "First remote should get PeerId(1)"
    );
    assert_eq!(
        net_cfg.outbound_peers[1].0,
        PeerId(2),
        "Second remote should get PeerId(2)"
    );
    assert_eq!(
        net_cfg.outbound_peers[2].0,
        PeerId(3),
        "Third remote should get PeerId(3)"
    );

    // Check addresses in outbound_peers
    assert_eq!(
        net_cfg.outbound_peers[0].1.port(),
        9001,
        "First remote addr should match"
    );
    assert_eq!(
        net_cfg.outbound_peers[1].1.port(),
        9002,
        "Second remote addr should match"
    );
    assert_eq!(
        net_cfg.outbound_peers[2].1.port(),
        9003,
        "Third remote addr should match"
    );

    // Check PeerValidatorMap
    assert_eq!(id_map.len(), 3, "PeerValidatorMap should have 3 entries");
    assert_eq!(
        id_map.get(&PeerId(1)),
        Some(ValidatorId::new(2)),
        "PeerId(1) should map to ValidatorId(2)"
    );
    assert_eq!(
        id_map.get(&PeerId(2)),
        Some(ValidatorId::new(3)),
        "PeerId(2) should map to ValidatorId(3)"
    );
    assert_eq!(
        id_map.get(&PeerId(3)),
        Some(ValidatorId::new(4)),
        "PeerId(3) should map to ValidatorId(4)"
    );

    // Check that non-existent PeerIds return None
    assert_eq!(id_map.get(&PeerId(0)), None);
    assert_eq!(id_map.get(&PeerId(99)), None);
}

/// Test that the wiring is consistent - running the same config twice gives the same result.
#[test]
fn build_net_config_and_id_map_is_deterministic() {
    let setup1 = create_test_setup();
    let setup2 = create_test_setup();

    let validator_config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(10),
            listen_addr: "127.0.0.1:8000".parse().unwrap(),
            consensus_pk: b"pk-10".to_vec(),
        },
        remotes: vec![
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(20),
                addr: "127.0.0.1:8001".parse().unwrap(),
                consensus_pk: b"pk-20".to_vec(),
            },
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(30),
                addr: "127.0.0.1:8002".parse().unwrap(),
                consensus_pk: b"pk-30".to_vec(),
            },
        ],
    };

    let (net_cfg1, id_map1) = build_net_config_and_id_map_for_tests(
        &validator_config,
        setup1.client_cfg,
        setup1.server_cfg,
        Duration::from_secs(5),
        Duration::from_secs(30),
        100,
    );

    let (net_cfg2, id_map2) = build_net_config_and_id_map_for_tests(
        &validator_config,
        setup2.client_cfg,
        setup2.server_cfg,
        Duration::from_secs(5),
        Duration::from_secs(30),
        100,
    );

    // NetServiceConfigs should have same peer assignments
    assert_eq!(net_cfg1.outbound_peers.len(), net_cfg2.outbound_peers.len());
    for i in 0..net_cfg1.outbound_peers.len() {
        assert_eq!(
            net_cfg1.outbound_peers[i].0, net_cfg2.outbound_peers[i].0,
            "PeerId at index {} should be the same",
            i
        );
        assert_eq!(
            net_cfg1.outbound_peers[i].1, net_cfg2.outbound_peers[i].1,
            "Address at index {} should be the same",
            i
        );
    }

    // PeerValidatorMaps should be identical
    assert_eq!(id_map1.len(), id_map2.len());
    for (peer_id, validator_id) in id_map1.iter() {
        assert_eq!(
            id_map2.get(peer_id),
            Some(*validator_id),
            "Mapping for {:?} should be the same",
            peer_id
        );
    }
}

/// Test that ConsensusNode can use the identity map consistently.
///
/// This test:
/// 1. Builds a `NodeValidatorConfig` with 1 local + 1 remote.
/// 2. Builds `(NetServiceConfig, PeerValidatorMap)` via the helper.
/// 3. Creates a `NetService` with that config and wraps into `ConsensusNode::with_id_map(...)`.
/// 4. Manually inserts a PeerId into PeerValidatorMap.
/// 5. Verifies that the identity map lookup gives the expected ValidatorId.
#[test]
fn consensus_node_with_validator_config_uses_id_map_consistently() {
    let setup = create_test_setup();

    let validator_config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:0".parse().unwrap(), // Use port 0 for auto-assign
            consensus_pk: b"pk-1".to_vec(),
        },
        remotes: vec![RemoteValidatorConfig {
            validator_id: ValidatorId::new(2),
            addr: "127.0.0.1:9999".parse().unwrap(), // Doesn't need to be reachable for this test
            consensus_pk: b"pk-2".to_vec(),
        }],
    };

    let (net_cfg, id_map) = build_net_config_and_id_map_for_tests(
        &validator_config,
        setup.client_cfg,
        setup.server_cfg,
        Duration::from_secs(5),
        Duration::from_secs(30),
        100,
    );

    // Create NetService and ConsensusNode with the pre-built id_map
    let net_service = NetService::new(net_cfg).expect("NetService::new failed");
    let node = ConsensusNode::with_id_map(net_service, id_map);

    // Verify the identity map is correctly populated
    assert_eq!(
        node.get_validator_for_peer(&PeerId(1)),
        Some(ValidatorId::new(2)),
        "PeerId(1) should map to ValidatorId(2)"
    );

    // Verify non-existent peers return None
    assert_eq!(
        node.get_validator_for_peer(&PeerId(99)),
        None,
        "Non-existent PeerId should return None"
    );
}

/// Test that identity map lookup works correctly when receiving a vote.
///
/// This is a more comprehensive test that:
/// 1. Creates a server ConsensusNode with a pre-populated identity map
/// 2. Connects a client peer
/// 3. The client sends a vote
/// 4. The server receives the vote and uses the identity map to look up the ValidatorId
/// 5. Verifies the mapping is correct
#[test]
fn consensus_node_identity_map_lookup_on_incoming_vote() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // The ValidatorId we expect for the client peer
    let expected_remote_validator_id = ValidatorId::new(42);

    // Create validator config for the server
    let validator_config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            consensus_pk: b"pk-1".to_vec(),
        },
        remotes: vec![], // No remotes in config, we'll add manually
    };

    // Build NetServiceConfig without any remotes (we'll have the client connect)
    let (net_cfg, mut id_map) = build_net_config_and_id_map_for_tests(
        &validator_config,
        client_cfg.clone(),
        server_cfg,
        Duration::from_millis(50),
        Duration::from_secs(60),
        100,
    );

    // Create NetService and ConsensusNode
    let net_service = NetService::new(net_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");

    // Pre-populate the id_map: The server will assign PeerId(1) to the first inbound connection.
    // We register that PeerId(1) maps to our expected ValidatorId.
    id_map.insert(PeerId(1), expected_remote_validator_id);

    let mut node = ConsensusNode::with_id_map(net_service, id_map);

    // Create a dummy vote
    let dummy_vote = make_dummy_vote_with_validator_index(7);
    let expected_vote = dummy_vote.clone();

    // Server thread: accept connection and receive vote
    let server_handle = thread::spawn(move || {
        // Step network until we have a connection
        for _ in 0..1000 {
            node.step_network().expect("step_network failed");
            if node.net_service().peers().len() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(
            node.net_service().peers().len() > 0,
            "No peer connected to server"
        );

        // Receive the vote
        let mut received_event = None;
        for _ in 0..1000 {
            let result: Result<ConsensusNetworkEvent<PeerId>, _> =
                node.with_consensus_network(|net| net.recv_one());

            match result {
                Ok(evt) => {
                    received_event = Some(evt);
                    break;
                }
                Err(_) => {
                    node.step_network().expect("step_network failed");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }

        let event = received_event.expect("Failed to receive vote event");

        // Extract the PeerId from the event and look up the ValidatorId
        match event {
            ConsensusNetworkEvent::IncomingVote { from, vote } => {
                // Use the identity map to look up the ValidatorId for this peer
                let looked_up_validator_id = node.get_validator_for_peer(&from);

                (from, vote, looked_up_validator_id)
            }
            other => panic!("expected IncomingVote, got {:?}", other),
        }
    });

    // Client side: Connect and send vote
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_vote(&dummy_vote)
            .expect("client broadcast_vote failed");
    }

    // Wait for server to receive and process
    let (peer_id, vote, looked_up_validator_id) =
        server_handle.join().expect("server thread panicked");

    // Verify the vote was received correctly
    assert_eq!(peer_id, PeerId(1), "Server should assign PeerId(1) to first inbound peer");
    assert_eq!(vote, expected_vote, "Vote should match");

    // Verify the identity map lookup worked correctly
    assert_eq!(
        looked_up_validator_id,
        Some(expected_remote_validator_id),
        "Identity map lookup should return the expected ValidatorId"
    );
}

/// Test that build_validator_key_registry() correctly creates a registry
/// from the NodeValidatorConfig.
///
/// This test:
/// 1. Creates a NodeValidatorConfig with local + N remotes
/// 2. Calls build_validator_key_registry()
/// 3. Asserts len() equals 1 + remotes.len()
/// 4. Asserts each validator_id has the expected ValidatorPublicKey bytes
#[test]
fn build_validator_key_registry_matches_config() {
    use cano_consensus::ValidatorPublicKey;

    let validator_config = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
            consensus_pk: format!("pk-{}", 1).into_bytes(),
        },
        remotes: vec![
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(2),
                addr: "127.0.0.1:9001".parse().unwrap(),
                consensus_pk: format!("pk-{}", 2).into_bytes(),
            },
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(3),
                addr: "127.0.0.1:9002".parse().unwrap(),
                consensus_pk: format!("pk-{}", 3).into_bytes(),
            },
            RemoteValidatorConfig {
                validator_id: ValidatorId::new(4),
                addr: "127.0.0.1:9003".parse().unwrap(),
                consensus_pk: format!("pk-{}", 4).into_bytes(),
            },
        ],
    };

    let registry = validator_config.build_validator_key_registry();

    // Check the length is 1 (local) + 3 (remotes) = 4
    assert_eq!(
        registry.len(),
        4,
        "Registry should have 4 entries (1 local + 3 remotes)"
    );
    assert!(!registry.is_empty());

    // Check each validator's public key is present with the correct bytes
    let expected_pk1 = ValidatorPublicKey(format!("pk-{}", 1).into_bytes());
    let expected_pk2 = ValidatorPublicKey(format!("pk-{}", 2).into_bytes());
    let expected_pk3 = ValidatorPublicKey(format!("pk-{}", 3).into_bytes());
    let expected_pk4 = ValidatorPublicKey(format!("pk-{}", 4).into_bytes());

    assert!(registry.contains(&ValidatorId::new(1)));
    assert_eq!(registry.get(&ValidatorId::new(1)), Some(&expected_pk1));

    assert!(registry.contains(&ValidatorId::new(2)));
    assert_eq!(registry.get(&ValidatorId::new(2)), Some(&expected_pk2));

    assert!(registry.contains(&ValidatorId::new(3)));
    assert_eq!(registry.get(&ValidatorId::new(3)), Some(&expected_pk3));

    assert!(registry.contains(&ValidatorId::new(4)));
    assert_eq!(registry.get(&ValidatorId::new(4)), Some(&expected_pk4));

    // Verify that non-existent validators return None
    assert!(!registry.contains(&ValidatorId::new(999)));
    assert_eq!(registry.get(&ValidatorId::new(999)), None);
}