use cano_wire::net::{
    NetworkDelegationCert, ClientInit, ServerAccept, ServerCookie,
    CERT_TYPE_NETWORK_DELEGATION, MSG_TYPE_CLIENT_INIT, MSG_TYPE_SERVER_ACCEPT, MSG_TYPE_SERVER_COOKIE,
};
use cano_wire::io::{WireEncode, WireDecode};

#[test]
fn roundtrip_network_delegation_cert() {
    let cert = NetworkDelegationCert {
        version: 1,
        validator_id: [0xAA; 32],
        root_key_id: [0xBB; 32],
        leaf_kem_suite_id: 0x01,
        leaf_kem_pk: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        not_before: 1700000000,
        not_after: 1800000000,
        ext_bytes: vec![0xAB, 0xCD],
        sig_suite_id: 0x02,
        sig_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let mut encoded = Vec::new();
    cert.encode(&mut encoded);

    // Verify the cert_type byte
    assert_eq!(encoded[0], CERT_TYPE_NETWORK_DELEGATION);

    let mut input = encoded.as_slice();
    let decoded = NetworkDelegationCert::decode(&mut input).unwrap();

    assert_eq!(cert, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_network_delegation_cert_empty_fields() {
    let cert = NetworkDelegationCert {
        version: 1,
        validator_id: [0x00; 32],
        root_key_id: [0xFF; 32],
        leaf_kem_suite_id: 0x00,
        leaf_kem_pk: vec![],
        not_before: 0,
        not_after: 0,
        ext_bytes: vec![],
        sig_suite_id: 0x00,
        sig_bytes: vec![],
    };

    let mut encoded = Vec::new();
    cert.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = NetworkDelegationCert::decode(&mut input).unwrap();

    assert_eq!(cert, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_client_init() {
    let client_init = ClientInit {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        client_random: [0xCC; 32],
        validator_id: [0xDD; 32],
        cookie: vec![0x01, 0x02, 0x03],
        kem_ct: vec![0x11, 0x22, 0x33, 0x44],
    };

    let mut encoded = Vec::new();
    client_init.encode(&mut encoded);

    // Verify the msg_type byte
    assert_eq!(encoded[0], MSG_TYPE_CLIENT_INIT);

    let mut input = encoded.as_slice();
    let decoded = ClientInit::decode(&mut input).unwrap();

    assert_eq!(client_init, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_client_init_empty_cookie_and_kem_ct() {
    let client_init = ClientInit {
        version: 1,
        kem_suite_id: 0x00,
        aead_suite_id: 0x00,
        client_random: [0x00; 32],
        validator_id: [0xFF; 32],
        cookie: vec![],
        kem_ct: vec![],
    };

    let mut encoded = Vec::new();
    client_init.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = ClientInit::decode(&mut input).unwrap();

    assert_eq!(client_init, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_server_accept() {
    let server_accept = ServerAccept {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        server_random: [0xAA; 32],
        validator_id: [0xBB; 32],
        client_random: [0xCC; 32],
        delegation_cert: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        flags: 0x0101,
    };

    let mut encoded = Vec::new();
    server_accept.encode(&mut encoded);

    // Verify the msg_type byte
    assert_eq!(encoded[0], MSG_TYPE_SERVER_ACCEPT);

    let mut input = encoded.as_slice();
    let decoded = ServerAccept::decode(&mut input).unwrap();

    assert_eq!(server_accept, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_server_accept_with_embedded_cert() {
    // First encode a NetworkDelegationCert
    let cert = NetworkDelegationCert {
        version: 1,
        validator_id: [0xAA; 32],
        root_key_id: [0xBB; 32],
        leaf_kem_suite_id: 0x01,
        leaf_kem_pk: vec![0x11, 0x22],
        not_before: 1700000000,
        not_after: 1800000000,
        ext_bytes: vec![],
        sig_suite_id: 0x02,
        sig_bytes: vec![0xDE, 0xAD],
    };
    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let server_accept = ServerAccept {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        server_random: [0xAA; 32],
        validator_id: [0xBB; 32],
        client_random: [0xCC; 32],
        delegation_cert: cert_bytes,
        flags: 0x0000,
    };

    let mut encoded = Vec::new();
    server_accept.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = ServerAccept::decode(&mut input).unwrap();

    assert_eq!(server_accept, decoded);
    assert!(input.is_empty());

    // Verify we can also decode the embedded cert
    let mut cert_input = decoded.delegation_cert.as_slice();
    let decoded_cert = NetworkDelegationCert::decode(&mut cert_input).unwrap();
    assert_eq!(cert, decoded_cert);
}

#[test]
fn roundtrip_server_cookie() {
    let server_cookie = ServerCookie {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        validator_id: [0xAA; 32],
        client_random: [0xBB; 32],
        cookie: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let mut encoded = Vec::new();
    server_cookie.encode(&mut encoded);

    // Verify the msg_type byte
    assert_eq!(encoded[0], MSG_TYPE_SERVER_COOKIE);

    let mut input = encoded.as_slice();
    let decoded = ServerCookie::decode(&mut input).unwrap();

    assert_eq!(server_cookie, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_server_cookie_empty() {
    let server_cookie = ServerCookie {
        version: 1,
        kem_suite_id: 0x00,
        aead_suite_id: 0x00,
        validator_id: [0x00; 32],
        client_random: [0xFF; 32],
        cookie: vec![],
    };

    let mut encoded = Vec::new();
    server_cookie.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = ServerCookie::decode(&mut input).unwrap();

    assert_eq!(server_cookie, decoded);
    assert!(input.is_empty());
}

#[test]
fn client_init_encoded_length() {
    // Test ClientInit with known-length fields
    let client_init = ClientInit {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        client_random: [0xCC; 32],
        validator_id: [0xDD; 32],
        cookie: vec![0x01, 0x02, 0x03],       // 3 bytes
        kem_ct: vec![0x11, 0x22, 0x33, 0x44], // 4 bytes
    };

    let mut encoded = Vec::new();
    client_init.encode(&mut encoded);

    // Expected length:
    // msg_type: 1 + version: 1 + kem_suite_id: 1 + aead_suite_id: 1 +
    // client_random: 32 + validator_id: 32 + cookie_len: 2 + cookie: 3 +
    // kem_ct_len: 2 + kem_ct: 4 = 79
    assert_eq!(encoded.len(), 1 + 1 + 1 + 1 + 32 + 32 + 2 + 3 + 2 + 4);

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = ClientInit::decode(&mut input).unwrap();
    assert_eq!(client_init, decoded);
}

#[test]
fn network_delegation_cert_encoded_length() {
    let cert = NetworkDelegationCert {
        version: 1,
        validator_id: [0xAA; 32],
        root_key_id: [0xBB; 32],
        leaf_kem_suite_id: 0x01,
        leaf_kem_pk: vec![0x11, 0x22, 0x33],  // 3 bytes
        not_before: 1700000000,
        not_after: 1800000000,
        ext_bytes: vec![0xAB, 0xCD],          // 2 bytes
        sig_suite_id: 0x02,
        sig_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF], // 4 bytes
    };

    let mut encoded = Vec::new();
    cert.encode(&mut encoded);

    // Expected length:
    // cert_type: 1 + version: 1 + validator_id: 32 + root_key_id: 32 +
    // leaf_kem_suite_id: 1 + reserved1: 1 + leaf_pk_len: 2 + leaf_kem_pk: 3 +
    // not_before: 8 + not_after: 8 + ext_len: 2 + ext_bytes: 2 +
    // sig_suite_id: 1 + reserved2: 1 + sig_len: 2 + sig_bytes: 4
    // = 1+1+32+32+1+1+2+3+8+8+2+2+1+1+2+4 = 101
    assert_eq!(encoded.len(), 1 + 1 + 32 + 32 + 1 + 1 + 2 + 3 + 8 + 8 + 2 + 2 + 1 + 1 + 2 + 4);

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = NetworkDelegationCert::decode(&mut input).unwrap();
    assert_eq!(cert, decoded);
}