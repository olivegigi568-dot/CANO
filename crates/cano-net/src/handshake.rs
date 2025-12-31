//! KEMTLS-PDK handshake engine for validator / inter-node connections.
//!
//! This module provides the client-side and server-side state machines for
//! establishing AEAD sessions using post-quantum KEM-based key exchange.

use std::sync::Arc;

use cano_crypto::CryptoProvider;
use cano_hash::net::network_delegation_cert_digest;
use cano_wire::io::WireDecode;
use cano_wire::net::{ClientInit, NetworkDelegationCert, ServerAccept};
use sha3::{Digest, Sha3_256};

use crate::error::NetError;
use crate::keys::SessionKeys;
use crate::session::AeadSession;

/// Simplified connection state: either in handshake or established.
#[derive(Debug)]
pub enum ConnectionState<'a> {
    /// Handshake in progress; no AEAD session yet.
    Handshaking,
    /// Established AEAD session ready for transport.
    Established(AeadSession<'a>),
}

/// Identifies which side of the KEMTLS handshake we are on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeSide {
    Client,
    Server,
}

/// Result of a completed handshake: AEAD session + peer identity info.
#[derive(Debug)]
pub struct HandshakeResult<'a> {
    /// The derived AEAD session (ready for use).
    pub session: AeadSession<'a>,
    /// Validator ID of the peer (from delegation cert).
    pub peer_validator_id: [u8; 32],
    /// KEM suite ID used for this session.
    pub kem_suite_id: u8,
    /// AEAD suite ID used for this session.
    pub aead_suite_id: u8,
}

/// Verify a NetworkDelegationCert against a trusted root public key.
///
/// `root_pk` is the long-term ValidatorNetwork root key for the validator,
/// which must match the `root_key_id` semantics used in the cert.
///
/// This uses cano-hash::net::network_delegation_cert_digest(cert) as the message
/// to be signed, and verifies using the suite indicated by `cert.sig_suite_id`.
pub fn verify_delegation_cert(
    crypto: &dyn CryptoProvider,
    cert: &NetworkDelegationCert,
    root_pk: &[u8],
) -> Result<(), NetError> {
    // 1) Resolve signature suite.
    let suite = crypto
        .signature_suite(cert.sig_suite_id)
        .ok_or(NetError::UnsupportedSuite(cert.sig_suite_id))?;

    // 2) Compute digest for the cert according to cano-hash.
    let digest = network_delegation_cert_digest(cert);

    // 3) Verify signature.
    suite
        .verify(root_pk, &digest, &cert.sig_bytes)
        .map_err(|_| NetError::KeySchedule("signature verify error"))?;

    Ok(())
}

/// Configuration inputs for a client-side handshake.
#[derive(Clone)]
pub struct ClientHandshakeConfig {
    /// KEM suite ID we want to use.
    pub kem_suite_id: u8,
    /// AEAD suite ID we want to use.
    pub aead_suite_id: u8,
    /// Crypto provider used to obtain KEM, AEAD, and signature suites.
    pub crypto: Arc<dyn CryptoProvider>,
    /// Root ValidatorNetwork public key for the peer we expect to talk to.
    pub peer_root_network_pk: Vec<u8>,
}

impl std::fmt::Debug for ClientHandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshakeConfig")
            .field("kem_suite_id", &self.kem_suite_id)
            .field("aead_suite_id", &self.aead_suite_id)
            .field("peer_root_network_pk", &self.peer_root_network_pk)
            .finish_non_exhaustive()
    }
}

/// Client-side KEMTLS handshake state.
pub struct ClientHandshake {
    cfg: ClientHandshakeConfig,
    /// Client-side ephemeral random data (randomness not modeled; caller passes).
    client_random: [u8; 32],
    /// Stored KEM encapsulated ciphertext produced in start().
    kem_ct: Option<Vec<u8>>,
    /// Stored KEM shared secret from encapsulation.
    shared_secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("cfg", &self.cfg)
            .field("client_random", &self.client_random)
            .field("kem_ct", &self.kem_ct.as_ref().map(|v| v.len()))
            .field("shared_secret", &self.shared_secret.as_ref().map(|_| "<hidden>"))
            .finish()
    }
}

impl ClientHandshake {
    /// Create a new client handshake with config and caller-provided client_random.
    pub fn new(cfg: ClientHandshakeConfig, client_random: [u8; 32]) -> Self {
        ClientHandshake {
            cfg,
            client_random,
            kem_ct: None,
            shared_secret: None,
        }
    }

    /// Build a ClientInit message for the peer validator_id.
    ///
    /// This:
    ///  - uses the configured KEM suite to encapsulate to `peer_kem_pk`,
    ///  - stores (kem_ct, shared_secret) locally,
    ///  - fills out ClientInit with suite IDs, client_random, validator_id, etc.
    pub fn start(
        &mut self,
        validator_id: [u8; 32],
        peer_kem_pk: &[u8],
    ) -> Result<ClientInit, NetError> {
        let kem = self
            .cfg
            .crypto
            .kem_suite(self.cfg.kem_suite_id)
            .ok_or(NetError::UnsupportedSuite(self.cfg.kem_suite_id))?;

        let (ct, ss) = kem
            .encaps(peer_kem_pk)
            .map_err(|_| NetError::KeySchedule("kem encaps failed"))?;

        self.kem_ct = Some(ct.clone());
        self.shared_secret = Some(ss);

        // Build ClientInit. Adjust to actual fields in cano-wire::net::ClientInit.
        Ok(ClientInit {
            version: 1,
            kem_suite_id: self.cfg.kem_suite_id,
            aead_suite_id: self.cfg.aead_suite_id,
            client_random: self.client_random,
            validator_id,
            cookie: Vec::new(), // no cookie for T25; DoS cookies can be added in later tasks.
            kem_ct: ct,
        })
    }

    /// Complete the client-side handshake after receiving ServerAccept.
    ///
    /// This:
    ///  - verifies the NetworkDelegationCert against peer_root_network_pk,
    ///  - computes a transcript hash over ClientInit + ServerAccept fields,
    ///  - derives SessionKeys and constructs an AeadSession.
    pub fn handle_server_accept<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        client_init: &ClientInit,
        accept: &ServerAccept,
    ) -> Result<HandshakeResult<'a>, NetError> {
        // 1) Parse and verify delegation cert from raw bytes.
        let mut cert_slice: &[u8] = &accept.delegation_cert;
        let delegation_cert = NetworkDelegationCert::decode(&mut cert_slice)
            .map_err(|_| NetError::KeySchedule("failed to parse delegation cert"))?;

        verify_delegation_cert(
            self.cfg.crypto.as_ref(),
            &delegation_cert,
            &self.cfg.peer_root_network_pk,
        )?;

        // 2) Check that validator_id matches what we expected.
        if delegation_cert.validator_id != client_init.validator_id {
            return Err(NetError::KeySchedule("validator_id mismatch in cert"));
        }

        // 3) Compute transcript hash (simplified for T25).
        // For now, use Sha3_256 over:
        //   "CANO:KEMTLS" || client_random || server_random || kem_ct
        let mut h = Sha3_256::new();
        h.update(b"CANO:KEMTLS");
        h.update(client_init.client_random);
        h.update(accept.server_random);
        h.update(&client_init.kem_ct);
        let transcript_hash = h.finalize();

        // 4) Use shared_secret from encapsulation.
        let shared = self
            .shared_secret
            .as_ref()
            .ok_or(NetError::KeySchedule("missing shared_secret"))?;

        // 5) Get key length from AEAD suite.
        let aead = crypto
            .aead_suite(client_init.aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(client_init.aead_suite_id))?;
        let key_len = aead.key_len();

        // 6) Derive session keys.
        let keys = SessionKeys::derive(
            shared,
            &transcript_hash,
            client_init.kem_suite_id,
            client_init.aead_suite_id,
            key_len,
        );

        // 7) Build AEAD session.
        let session = AeadSession::new(crypto, client_init.aead_suite_id, &keys)?;

        Ok(HandshakeResult {
            session,
            peer_validator_id: delegation_cert.validator_id,
            kem_suite_id: client_init.kem_suite_id,
            aead_suite_id: client_init.aead_suite_id,
        })
    }
}

/// Configuration inputs for a server-side handshake.
#[derive(Clone)]
pub struct ServerHandshakeConfig {
    /// KEM suite ID this node supports for validator networking.
    pub kem_suite_id: u8,
    /// AEAD suite ID this node supports for validator networking.
    pub aead_suite_id: u8,
    /// Crypto provider.
    pub crypto: Arc<dyn CryptoProvider>,
    /// This validator's root network public key (for delegations).
    /// In a PDK model, the delegation cert is precomputed; for T25,
    /// we will assume we already have a valid NetworkDelegationCert.
    pub local_root_network_pk: Vec<u8>,
    /// Pre-built delegation cert we send to clients (encoded as raw bytes).
    pub local_delegation_cert: Vec<u8>,
    /// KEM private key for this node (corresponding to cert.leaf_kem_pk).
    pub local_kem_sk: Vec<u8>,
}

impl std::fmt::Debug for ServerHandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshakeConfig")
            .field("kem_suite_id", &self.kem_suite_id)
            .field("aead_suite_id", &self.aead_suite_id)
            .field("local_root_network_pk", &self.local_root_network_pk)
            .field("local_delegation_cert", &self.local_delegation_cert.len())
            .field("local_kem_sk", &"<hidden>")
            .finish()
    }
}

/// Server-side KEMTLS handshake state.
pub struct ServerHandshake {
    cfg: ServerHandshakeConfig,
    /// Server's random contribution.
    server_random: [u8; 32],
}

impl std::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("cfg", &self.cfg)
            .field("server_random", &self.server_random)
            .finish()
    }
}

impl ServerHandshake {
    pub fn new(cfg: ServerHandshakeConfig, server_random: [u8; 32]) -> Self {
        ServerHandshake { cfg, server_random }
    }

    /// Handle a ClientInit and produce ServerAccept plus a HandshakeResult.
    pub fn handle_client_init<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        init: &ClientInit,
    ) -> Result<(ServerAccept, HandshakeResult<'a>), NetError> {
        // 1) Ensure suites match what we support.
        if init.kem_suite_id != self.cfg.kem_suite_id {
            return Err(NetError::UnsupportedSuite(init.kem_suite_id));
        }
        if init.aead_suite_id != self.cfg.aead_suite_id {
            return Err(NetError::UnsupportedSuite(init.aead_suite_id));
        }

        // 2) KEM decapsulation using local secret key.
        let kem = self
            .cfg
            .crypto
            .kem_suite(self.cfg.kem_suite_id)
            .ok_or(NetError::UnsupportedSuite(self.cfg.kem_suite_id))?;

        let shared = kem
            .decaps(&self.cfg.local_kem_sk, &init.kem_ct)
            .map_err(|_| NetError::KeySchedule("kem decaps failed"))?;

        // 3) Compute transcript hash (same formula as client).
        let mut h = Sha3_256::new();
        h.update(b"CANO:KEMTLS");
        h.update(init.client_random);
        h.update(self.server_random);
        h.update(&init.kem_ct);
        let transcript_hash = h.finalize();

        // 4) Get key length from AEAD suite.
        let aead = crypto
            .aead_suite(init.aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(init.aead_suite_id))?;
        let key_len = aead.key_len();

        // 5) Derive session keys.
        let keys = SessionKeys::derive(
            &shared,
            &transcript_hash,
            init.kem_suite_id,
            init.aead_suite_id,
            key_len,
        );

        // 6) Build AEAD session.
        let session = AeadSession::new(crypto, init.aead_suite_id, &keys)?;

        // 7) Build ServerAccept.
        let accept = ServerAccept {
            version: 1,
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
            server_random: self.server_random,
            validator_id: init.validator_id,
            client_random: init.client_random,
            delegation_cert: self.cfg.local_delegation_cert.clone(),
            flags: 0,
        };

        let result = HandshakeResult {
            session,
            peer_validator_id: init.validator_id,
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
        };

        Ok((accept, result))
    }
}