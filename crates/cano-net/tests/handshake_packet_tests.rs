//! Tests for handshake packet framing layer.

use cano_net::{
    pack_client_init, pack_server_accept, pack_server_cookie, unpack_client_init,
    unpack_server_accept, unpack_server_cookie, HandshakePacket, HANDSHAKE_TYPE_CLIENT_INIT,
    HANDSHAKE_TYPE_SERVER_ACCEPT, HANDSHAKE_TYPE_SERVER_COOKIE,
};
use cano_wire::net::{ClientInit, ServerAccept, ServerCookie};

// ============================================================================
// Roundtrip Tests
// ============================================================================

#[test]
fn client_init_roundtrip() {
    // Build a dummy ClientInit
    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let msg = ClientInit {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        client_random,
        validator_id,
        cookie: vec![0xAA, 0xBB, 0xCC],
        kem_ct: vec![0x11, 0x22, 0x33, 0x44],
    };

    // Pack → encode → decode → unpack
    let pkt = pack_client_init(&msg).expect("pack_client_init should succeed");
    assert_eq!(pkt.msg_type, HANDSHAKE_TYPE_CLIENT_INIT);

    let frame = pkt.encode();
    assert!(frame.len() >= 3);

    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);

    let msg2 = unpack_client_init(&pkt2).expect("unpack_client_init should succeed");
    assert_eq!(msg, msg2);
}

#[test]
fn server_accept_roundtrip() {
    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let msg = ServerAccept {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        server_random,
        validator_id,
        client_random,
        delegation_cert: vec![0xDE, 0xAD, 0xBE, 0xEF],
        flags: 0x00,
    };

    // Pack → encode → decode → unpack
    let pkt = pack_server_accept(&msg).expect("pack_server_accept should succeed");
    assert_eq!(pkt.msg_type, HANDSHAKE_TYPE_SERVER_ACCEPT);

    let frame = pkt.encode();
    assert!(frame.len() >= 3);

    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);

    let msg2 = unpack_server_accept(&pkt2).expect("unpack_server_accept should succeed");
    assert_eq!(msg, msg2);
}

#[test]
fn server_cookie_roundtrip() {
    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let msg = ServerCookie {
        version: 1,
        kem_suite_id: 0x01,
        aead_suite_id: 0x02,
        validator_id,
        client_random,
        cookie: vec![0xCA, 0xFE, 0xBA, 0xBE],
    };

    // Pack → encode → decode → unpack
    let pkt = pack_server_cookie(&msg).expect("pack_server_cookie should succeed");
    assert_eq!(pkt.msg_type, HANDSHAKE_TYPE_SERVER_COOKIE);

    let frame = pkt.encode();
    assert!(frame.len() >= 3);

    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);

    let msg2 = unpack_server_cookie(&pkt2).expect("unpack_server_cookie should succeed");
    assert_eq!(msg, msg2);
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn decode_fails_on_too_short_buffer() {
    // Less than 3 bytes (header is 3 bytes: 1 for type + 2 for length)
    let short_buf = vec![0x01, 0x00];
    let result = HandshakePacket::decode(&short_buf);
    assert!(result.is_err());

    let empty_buf: Vec<u8> = vec![];
    let result2 = HandshakePacket::decode(&empty_buf);
    assert!(result2.is_err());
}

#[test]
fn decode_fails_on_truncated_payload() {
    // Header says payload is 10 bytes, but we only provide 5
    let mut buf = vec![HANDSHAKE_TYPE_CLIENT_INIT];
    buf.extend_from_slice(&10u16.to_be_bytes()); // length = 10
    buf.extend_from_slice(&[0u8; 5]); // only 5 bytes of payload

    let result = HandshakePacket::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn unpack_client_init_fails_on_wrong_type() {
    // Create a packet with SERVER_ACCEPT type
    let pkt = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_SERVER_ACCEPT,
        payload: vec![0x00],
    };

    let result = unpack_client_init(&pkt);
    assert!(result.is_err());
}

#[test]
fn unpack_server_accept_fails_on_wrong_type() {
    // Create a packet with CLIENT_INIT type
    let pkt = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0x00],
    };

    let result = unpack_server_accept(&pkt);
    assert!(result.is_err());
}

#[test]
fn unpack_server_cookie_fails_on_wrong_type() {
    // Create a packet with CLIENT_INIT type
    let pkt = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0x00],
    };

    let result = unpack_server_cookie(&pkt);
    assert!(result.is_err());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn empty_payload_packet() {
    // Test that we can encode/decode a packet with empty payload
    let pkt = HandshakePacket {
        msg_type: 0xFF,
        payload: vec![],
    };

    let frame = pkt.encode();
    assert_eq!(frame.len(), 3); // 1 byte type + 2 bytes length + 0 bytes payload

    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);
}

#[test]
fn large_payload_packet() {
    // Test with a larger payload (but within u16 limits)
    let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

    let pkt = HandshakePacket {
        msg_type: 0x42,
        payload,
    };

    let frame = pkt.encode();
    assert_eq!(frame.len(), 3 + 1000);

    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);
}

#[test]
fn decode_ignores_trailing_bytes() {
    // Build a valid packet, then append extra bytes
    let pkt = HandshakePacket {
        msg_type: 0x01,
        payload: vec![0xAA, 0xBB],
    };

    let mut frame = pkt.encode();
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // Extra trailing bytes

    // Decode should succeed and ignore trailing bytes
    let pkt2 = HandshakePacket::decode(&frame).expect("decode should succeed");
    assert_eq!(pkt, pkt2);
}