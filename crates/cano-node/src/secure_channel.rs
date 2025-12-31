//! Secure channel abstraction for encrypted TCP communication.
//!
//! This module provides `SecureChannel`, which combines a `TcpStream` with a
//! `Connection` (from cano-net) to perform KEMTLS handshakes and send/receive
//! encrypted application data.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use cano_net::{
    read_handshake_packet, read_transport_frame, write_handshake_packet, write_transport_frame,
    ClientConnectionConfig, Connection, HandshakePacket, NetError, ServerConnectionConfig,
    TransportFrame,
};

/// Default timeout for socket read/write operations (in seconds).
const DEFAULT_SOCKET_TIMEOUT_SECS: u64 = 10;

/// Error type for SecureChannel operations.
///
/// Separates I/O errors from protocol/crypto errors.
#[derive(Debug)]
pub enum ChannelError {
    /// I/O error (TCP read/write failure).
    Io(io::Error),
    /// Protocol or crypto error from cano-net.
    Net(NetError),
}

impl From<io::Error> for ChannelError {
    fn from(err: io::Error) -> Self {
        ChannelError::Io(err)
    }
}

impl From<NetError> for ChannelError {
    fn from(err: NetError) -> Self {
        ChannelError::Net(err)
    }
}

/// Configure socket options for responsiveness.
fn configure_socket(stream: &TcpStream) {
    stream.set_nodelay(true).ok();
    stream
        .set_read_timeout(Some(Duration::from_secs(DEFAULT_SOCKET_TIMEOUT_SECS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(DEFAULT_SOCKET_TIMEOUT_SECS)))
        .ok();
}

/// A secure, encrypted TCP channel.
///
/// `SecureChannel` wraps a `TcpStream` and an established `Connection` to
/// provide encrypted application-level messaging over TCP.
///
/// # Invariant
///
/// By the time a `SecureChannel` is constructed, the KEMTLS handshake is
/// complete and `conn.is_established()` returns `true`.
#[derive(Debug)]
pub struct SecureChannel {
    stream: TcpStream,
    conn: Connection,
}

impl SecureChannel {
    /// Blocking client-side connect + KEMTLS handshake.
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote socket address (host:port)
    /// * `cfg` - Client handshake / suite configuration
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the TCP connection fails, the handshake fails,
    /// or the protocol is violated.
    pub fn connect(addr: &str, cfg: ClientConnectionConfig) -> Result<Self, ChannelError> {
        let mut stream = TcpStream::connect(addr)?;
        configure_socket(&stream);

        // 1. Create client Connection
        let mut conn = Connection::new_client(cfg);

        // 2. Start handshake, get the first frame to send
        let first = conn.start_handshake()?;

        // 3. Decode into HandshakePacket and send via framed_io
        let pkt = HandshakePacket::decode(&first)?;
        write_handshake_packet(&mut stream, &pkt)?;

        // 4. Read server reply as HandshakePacket
        let reply_pkt = read_handshake_packet(&mut stream)?;

        // 5. Let Connection process the reply
        let reply_bytes_opt = conn.handle_handshake_frame(&reply_pkt.encode())?;

        // Client should not produce any further handshake frames
        if reply_bytes_opt.is_some() {
            return Err(NetError::Protocol(
                "client handshake produced unexpected additional frame after server reply",
            )
            .into());
        }

        if !conn.is_established() {
            return Err(NetError::Protocol("client handshake not established").into());
        }

        Ok(SecureChannel { stream, conn })
    }

    /// Blocking server-side handshake on an already-accepted `TcpStream`.
    ///
    /// Does not call `accept`; the caller must accept connections and pass the
    /// stream in.
    ///
    /// # Arguments
    ///
    /// * `stream` - An already-accepted TCP stream
    /// * `cfg` - Server handshake / suite configuration
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the handshake fails or the protocol is violated.
    pub fn from_accepted(
        mut stream: TcpStream,
        cfg: ServerConnectionConfig,
    ) -> Result<Self, ChannelError> {
        configure_socket(&stream);

        // 1. Create server Connection
        let mut conn = Connection::new_server(cfg);

        // 2. Read client's ClientInit packet
        let client_pkt = read_handshake_packet(&mut stream)?;

        // 3. Let Connection process and produce ServerAccept
        let reply_bytes_opt = conn.handle_handshake_frame(&client_pkt.encode())?;
        let reply_bytes = reply_bytes_opt.ok_or_else(|| {
            ChannelError::Net(NetError::Protocol("server did not produce reply"))
        })?;

        // 4. Send ServerAccept
        let reply_pkt = HandshakePacket::decode(&reply_bytes)?;
        write_handshake_packet(&mut stream, &reply_pkt)?;

        if !conn.is_established() {
            return Err(NetError::Protocol("server handshake not established").into());
        }

        Ok(SecureChannel { stream, conn })
    }

    /// Encrypt and send an application message.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if encryption fails or the TCP write fails.
    pub fn send_app(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
        let frame_bytes = self.conn.encrypt_app(plaintext)?;
        let frame = TransportFrame::decode(&frame_bytes)?;
        write_transport_frame(&mut self.stream, &frame)?;
        Ok(())
    }

    /// Receive and decrypt a single application message.
    ///
    /// This blocks until one full transport frame is read or an I/O error occurs.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the TCP read fails or decryption fails.
    pub fn recv_app(&mut self) -> Result<Vec<u8>, ChannelError> {
        let frame = read_transport_frame(&mut self.stream)?;
        let plaintext = self.conn.decrypt_app(&frame.encode()?)?;
        Ok(plaintext)
    }

    /// Check if the connection is established and ready for app data.
    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }
}