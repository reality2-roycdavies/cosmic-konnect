//! TCP listener for incoming connections
//!
//! Listens for incoming CKP connections and handles the protocol.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::PROTOCOL_VERSION;
use crate::error::DaemonError;
use crate::AppState;

/// CKP protocol magic bytes
const MAGIC: &[u8; 2] = b"CK";

/// Maximum message size (1MB)
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Run the transport listener
pub async fn run(state: Arc<RwLock<AppState>>) -> Result<(), DaemonError> {
    let port = {
        let state_guard = state.read().await;
        state_guard.config.tcp_port
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = TcpListener::bind(addr).await?;
    info!("TCP listener started on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("Incoming connection from {}", peer_addr);

                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer_addr, state_clone).await {
                        warn!("Connection from {} error: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Handle a single connection
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<RwLock<AppState>>,
) -> Result<(), DaemonError> {
    // Read header: magic (2) + version (1) + flags (1) + length (4)
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;

    // Verify magic
    if &header[0..2] != MAGIC {
        return Err(DaemonError::Transport("Invalid magic bytes".into()));
    }

    let version = header[2];
    let flags = header[3];
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    debug!("Received message: version={}, flags={}, length={}", version, flags, length);

    // Validate length
    if length > MAX_MESSAGE_SIZE {
        return Err(DaemonError::Transport(format!("Message too large: {}", length)));
    }

    // Read message body
    let mut body = vec![0u8; length as usize];
    stream.read_exact(&mut body).await?;

    // Parse message (MessagePack)
    let message: serde_json::Value = rmp_serde::from_slice(&body)?;

    debug!("Message from {}: {:?}", peer_addr, message);

    // Handle message type
    let msg_type = message["type"].as_str().unwrap_or("unknown");

    match msg_type {
        "identity" => {
            handle_identity(&mut stream, &message, &state).await?;
        }
        "ping" => {
            handle_ping(&mut stream, &message).await?;
        }
        _ => {
            debug!("Unknown message type: {}", msg_type);
        }
    }

    Ok(())
}

/// Handle identity message
async fn handle_identity(
    stream: &mut TcpStream,
    message: &serde_json::Value,
    state: &Arc<RwLock<AppState>>,
) -> Result<(), DaemonError> {
    let device_id = message["device_id"].as_str().unwrap_or("unknown");
    let device_name = message["device_name"].as_str().unwrap_or("Unknown Device");

    info!("Identity from: {} ({})", device_name, device_id);

    // Send our identity
    let our_identity = {
        let state_guard = state.read().await;
        serde_json::json!({
            "type": "identity",
            "device_id": state_guard.config.identity.device_id,
            "device_name": state_guard.config.identity.device_name,
            "device_type": state_guard.config.identity.device_type.to_string(),
            "protocol_version": PROTOCOL_VERSION,
        })
    };

    send_message(stream, &our_identity).await?;

    Ok(())
}

/// Handle ping message
async fn handle_ping(
    stream: &mut TcpStream,
    message: &serde_json::Value,
) -> Result<(), DaemonError> {
    let ping_msg = message["message"].as_str();
    debug!("Ping received: {:?}", ping_msg);

    // Send pong
    let pong = serde_json::json!({
        "type": "pong",
        "message": ping_msg,
    });

    send_message(stream, &pong).await?;

    Ok(())
}

/// Send a message over the stream
async fn send_message(
    stream: &mut TcpStream,
    message: &serde_json::Value,
) -> Result<(), DaemonError> {
    // Serialize to MessagePack
    let body = rmp_serde::to_vec(message)?;

    // Build header
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(MAGIC);
    header.push(PROTOCOL_VERSION);
    header.push(0); // flags
    header.extend_from_slice(&(body.len() as u32).to_be_bytes());

    // Send header + body
    stream.write_all(&header).await?;
    stream.write_all(&body).await?;

    Ok(())
}
