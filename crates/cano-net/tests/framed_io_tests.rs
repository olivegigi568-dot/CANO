//! Tests for framed I/O helpers.
//!
//! These tests verify the blocking I/O utilities for HandshakePacket and TransportFrame
//! work correctly with various stream conditions.

use std::io::{self, Cursor, ErrorKind, Read, Write};

use cano_net::{
    read_handshake_packet, read_transport_frame, write_handshake_packet, write_transport_frame,
    HandshakePacket, TransportFrame, MAX_HANDSHAKE_PAYLOAD, MAX_TRANSPORT_CIPHERTEXT,
    HANDSHAKE_TYPE_CLIENT_INIT, TRANSPORT_TYPE_APP_MESSAGE,
};

// ============================================================================
// Helper: ChunkedReader for testing partial reads
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
// Helper: VecStream for read+write testing
// ============================================================================

/// A simple in-memory stream that supports both Read and Write.
/// Data written can be read back by resetting the position.
struct VecStream {
    data: Vec<u8>,
    pos: usize,
}

impl VecStream {
    fn new() -> Self {
        VecStream {
            data: Vec::new(),
            pos: 0,
        }
    }

    fn reset(&mut self) {
        self.pos = 0;
    }
}

impl Write for VecStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for VecStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.data[self.pos..];
        let to_read = buf.len().min(available.len());
        buf[..to_read].copy_from_slice(&available[..to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

// ============================================================================
// 3.1 Happy-path roundtrips with in-memory streams
// ============================================================================

#[test]
fn test_handshake_roundtrip() {
    // Construct a valid HandshakePacket
    let packet = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0xAA, 0xBB, 0xCC, 0xDD],
    };

    // Write to stream
    let mut stream = VecStream::new();
    write_handshake_packet(&mut stream, &packet).expect("write should succeed");

    // Reset and read back
    stream.reset();
    let decoded = read_handshake_packet(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload, packet.payload);
}

#[test]
fn test_handshake_roundtrip_with_cursor() {
    // Using std::io::Cursor
    let packet = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let mut buf = Vec::new();
    {
        let mut cursor = Cursor::new(&mut buf);
        write_handshake_packet(&mut cursor, &packet).expect("write should succeed");
    }

    let mut cursor = Cursor::new(&buf);
    let decoded = read_handshake_packet(&mut cursor).expect("read should succeed");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload, packet.payload);
}

#[test]
fn test_transport_roundtrip() {
    // Build a TransportFrame
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
    };

    // Write to stream
    let mut stream = VecStream::new();
    write_transport_frame(&mut stream, &frame).expect("write should succeed");

    // Reset and read back
    stream.reset();
    let decoded = read_transport_frame(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext, frame.ciphertext);
}

#[test]
fn test_transport_roundtrip_with_cursor() {
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: vec![0x01, 0x02, 0x03, 0x04],
    };

    let mut buf = Vec::new();
    {
        let mut cursor = Cursor::new(&mut buf);
        write_transport_frame(&mut cursor, &frame).expect("write should succeed");
    }

    let mut cursor = Cursor::new(&buf);
    let decoded = read_transport_frame(&mut cursor).expect("read should succeed");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext, frame.ciphertext);
}

// ============================================================================
// 3.2 Partial-read behavior
// ============================================================================

#[test]
fn test_handshake_read_with_fragmented_stream_chunk_1() {
    // Create a handshake packet
    let packet = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };

    // Encode to wire format
    let encoded = packet.encode();

    // Wrap in ChunkedReader with max_chunk = 1 (byte-by-byte reads)
    let cursor = Cursor::new(encoded);
    let mut chunked = ChunkedReader::new(cursor, 1);

    let decoded = read_handshake_packet(&mut chunked).expect("read should succeed with chunked stream");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload, packet.payload);
}

#[test]
fn test_handshake_read_with_fragmented_stream_chunk_2() {
    let packet = HandshakePacket {
        msg_type: 0x02,
        payload: (0..100).collect(),
    };

    let encoded = packet.encode();

    // Wrap in ChunkedReader with max_chunk = 2
    let cursor = Cursor::new(encoded);
    let mut chunked = ChunkedReader::new(cursor, 2);

    let decoded = read_handshake_packet(&mut chunked).expect("read should succeed with chunked stream");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload, packet.payload);
}

#[test]
fn test_transport_read_with_fragmented_stream_chunk_1() {
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    };

    let encoded = frame.encode().expect("encode should succeed");

    // Wrap in ChunkedReader with max_chunk = 1 (byte-by-byte reads)
    let cursor = Cursor::new(encoded);
    let mut chunked = ChunkedReader::new(cursor, 1);

    let decoded = read_transport_frame(&mut chunked).expect("read should succeed with chunked stream");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext, frame.ciphertext);
}

#[test]
fn test_transport_read_with_fragmented_stream_chunk_2() {
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: (0..200).collect(),
    };

    let encoded = frame.encode().expect("encode should succeed");

    // Wrap in ChunkedReader with max_chunk = 2
    let cursor = Cursor::new(encoded);
    let mut chunked = ChunkedReader::new(cursor, 2);

    let decoded = read_transport_frame(&mut chunked).expect("read should succeed with chunked stream");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext, frame.ciphertext);
}

// ============================================================================
// 3.3 Error cases
// ============================================================================

#[test]
fn test_truncated_handshake_header_1_byte() {
    // Only 1 byte of header (need 3)
    let buf = vec![0x01];
    let mut cursor = Cursor::new(buf);

    let result = read_handshake_packet(&mut cursor);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_truncated_handshake_header_2_bytes() {
    // Only 2 bytes of header (need 3)
    let buf = vec![0x01, 0x00];
    let mut cursor = Cursor::new(buf);

    let result = read_handshake_packet(&mut cursor);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_truncated_handshake_payload() {
    // Header says payload is 10 bytes, but we only provide 5
    let mut buf = vec![HANDSHAKE_TYPE_CLIENT_INIT];
    buf.extend_from_slice(&10u16.to_be_bytes()); // length = 10
    buf.extend_from_slice(&[0u8; 5]); // only 5 bytes of payload

    let mut cursor = Cursor::new(buf);
    let result = read_handshake_packet(&mut cursor);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_handshake_length_exceeds_max() {
    // Craft a header with length > MAX_HANDSHAKE_PAYLOAD
    // Note: MAX_HANDSHAKE_PAYLOAD (16384) + 1 = 16385, well within u16::MAX (65535)
    let exceeds_max = (MAX_HANDSHAKE_PAYLOAD + 1) as u16;
    let mut buf = vec![HANDSHAKE_TYPE_CLIENT_INIT];
    buf.extend_from_slice(&exceeds_max.to_be_bytes());
    // Don't need to provide actual payload since we should fail before reading it

    let mut cursor = Cursor::new(buf);
    let result = read_handshake_packet(&mut cursor);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn test_truncated_transport_header_1_byte() {
    // Only 1 byte of header (need 5)
    let buf = vec![0x01];
    let mut cursor = Cursor::new(buf);

    let result = read_transport_frame(&mut cursor);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_truncated_transport_header_4_bytes() {
    // Only 4 bytes of header (need 5)
    let buf = vec![0x01, 0x00, 0x00, 0x00];
    let mut cursor = Cursor::new(buf);

    let result = read_transport_frame(&mut cursor);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_truncated_transport_payload() {
    // Header says ciphertext is 10 bytes, but we only provide 5
    let mut buf = vec![TRANSPORT_TYPE_APP_MESSAGE];
    buf.extend_from_slice(&10u32.to_be_bytes()); // length = 10
    buf.extend_from_slice(&[0u8; 5]); // only 5 bytes of ciphertext

    let mut cursor = Cursor::new(buf);
    let result = read_transport_frame(&mut cursor);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn test_transport_length_exceeds_max() {
    // Craft a header with length > MAX_TRANSPORT_CIPHERTEXT
    // Note: MAX_TRANSPORT_CIPHERTEXT (16777216) + 1 = 16777217, well within u32::MAX
    let exceeds_max = (MAX_TRANSPORT_CIPHERTEXT + 1) as u32;
    let mut buf = vec![TRANSPORT_TYPE_APP_MESSAGE];
    buf.extend_from_slice(&exceeds_max.to_be_bytes());
    // Don't need to provide actual payload since we should fail before reading it

    let mut cursor = Cursor::new(buf);
    let result = read_transport_frame(&mut cursor);

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
}

// ============================================================================
// Additional edge cases
// ============================================================================

#[test]
fn test_handshake_empty_payload() {
    let packet = HandshakePacket {
        msg_type: 0xFF,
        payload: vec![],
    };

    let mut stream = VecStream::new();
    write_handshake_packet(&mut stream, &packet).expect("write should succeed");

    stream.reset();
    let decoded = read_handshake_packet(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload, packet.payload);
}

#[test]
fn test_transport_empty_ciphertext() {
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: vec![],
    };

    let mut stream = VecStream::new();
    write_transport_frame(&mut stream, &frame).expect("write should succeed");

    stream.reset();
    let decoded = read_transport_frame(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext, frame.ciphertext);
}

#[test]
fn test_handshake_max_valid_payload() {
    // Test with a payload at the maximum allowed size
    let packet = HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: vec![0xAB; MAX_HANDSHAKE_PAYLOAD],
    };

    let mut stream = VecStream::new();
    write_handshake_packet(&mut stream, &packet).expect("write should succeed");

    stream.reset();
    let decoded = read_handshake_packet(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, packet.msg_type);
    assert_eq!(decoded.payload.len(), MAX_HANDSHAKE_PAYLOAD);
}

#[test]
fn test_transport_large_ciphertext() {
    // Test with a moderately large ciphertext (1 MiB)
    let frame = TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext: vec![0xCD; 1024 * 1024],
    };

    let mut stream = VecStream::new();
    write_transport_frame(&mut stream, &frame).expect("write should succeed");

    stream.reset();
    let decoded = read_transport_frame(&mut stream).expect("read should succeed");

    assert_eq!(decoded.msg_type, frame.msg_type);
    assert_eq!(decoded.ciphertext.len(), 1024 * 1024);
}

#[test]
fn test_multiple_handshake_packets_sequential() {
    // Write multiple packets to the same stream, then read them back
    let packets = vec![
        HandshakePacket {
            msg_type: 0x01,
            payload: vec![0x11],
        },
        HandshakePacket {
            msg_type: 0x02,
            payload: vec![0x22, 0x33],
        },
        HandshakePacket {
            msg_type: 0x03,
            payload: vec![0x44, 0x55, 0x66],
        },
    ];

    let mut stream = VecStream::new();
    for packet in &packets {
        write_handshake_packet(&mut stream, packet).expect("write should succeed");
    }

    stream.reset();
    for expected in &packets {
        let decoded = read_handshake_packet(&mut stream).expect("read should succeed");
        assert_eq!(decoded.msg_type, expected.msg_type);
        assert_eq!(decoded.payload, expected.payload);
    }
}

#[test]
fn test_multiple_transport_frames_sequential() {
    // Write multiple frames to the same stream, then read them back
    let frames = vec![
        TransportFrame {
            msg_type: TRANSPORT_TYPE_APP_MESSAGE,
            ciphertext: vec![0xAA],
        },
        TransportFrame {
            msg_type: TRANSPORT_TYPE_APP_MESSAGE,
            ciphertext: vec![0xBB, 0xCC],
        },
        TransportFrame {
            msg_type: TRANSPORT_TYPE_APP_MESSAGE,
            ciphertext: vec![0xDD, 0xEE, 0xFF],
        },
    ];

    let mut stream = VecStream::new();
    for frame in &frames {
        write_transport_frame(&mut stream, frame).expect("write should succeed");
    }

    stream.reset();
    for expected in &frames {
        let decoded = read_transport_frame(&mut stream).expect("read should succeed");
        assert_eq!(decoded.msg_type, expected.msg_type);
        assert_eq!(decoded.ciphertext, expected.ciphertext);
    }
}