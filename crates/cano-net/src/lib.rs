pub mod connection;
pub mod error;
pub mod framed_io;
pub mod handshake;
pub mod handshake_packet;
pub mod hkdf;
pub mod keys;
pub mod session;
pub mod transport;

pub use connection::{ClientConnectionConfig, Connection, ServerConnectionConfig};
pub use error::NetError;
pub use framed_io::{
    read_handshake_packet, read_transport_frame, write_handshake_packet, write_transport_frame,
    MAX_HANDSHAKE_PAYLOAD, MAX_TRANSPORT_CIPHERTEXT,
};
pub use handshake::{
    ClientHandshake, ClientHandshakeConfig, ConnectionState, HandshakeResult, HandshakeSide,
    ServerHandshake, ServerHandshakeConfig,
};
pub use handshake_packet::{
    pack_client_init, pack_server_accept, pack_server_cookie, unpack_client_init,
    unpack_server_accept, unpack_server_cookie, HandshakePacket, HANDSHAKE_TYPE_CLIENT_INIT,
    HANDSHAKE_TYPE_SERVER_ACCEPT, HANDSHAKE_TYPE_SERVER_COOKIE,
};
pub use keys::SessionKeys;
pub use session::{AeadDirection, AeadSession};
pub use transport::{
    decrypt_app_frame, encrypt_app_frame, TransportFrame, TRANSPORT_TYPE_APP_MESSAGE,
};