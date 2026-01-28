//! CKP Connection handling
//!
//! Manages TCP connections between devices with encryption.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use super::crypto::{
    derive_pairing_key, generate_session_nonce, generate_verification_code, KeyPair, PairingInfo,
    PUBLIC_KEY_SIZE,
};
use super::message::*;
use super::{CONNECTION_TIMEOUT_SECS, MAGIC, MAX_MESSAGE_SIZE, TCP_PORT};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Identified,
    Pairing,
    Encrypted,
    Disconnected,
}

/// Events from a connection
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    Connected {
        device_id: String,
        device_name: String,
        address: SocketAddr,
    },
    Identified {
        device_id: String,
        identity: Identity,
    },
    PairingRequested {
        device_id: String,
        device_name: String,
        verification_code: String,
    },
    Paired {
        device_id: String,
        device_name: String,
    },
    PairingRejected {
        device_id: String,
        reason: String,
    },
    MessageReceived {
        device_id: String,
        message: Message,
    },
    Disconnected {
        device_id: String,
        reason: Option<String>,
    },
}

/// Commands to send to a connection
#[derive(Debug)]
pub enum ConnectionCommand {
    Send(Message),
    RequestPairing(KeyPair),
    AcceptPairing,
    RejectPairing,
    Disconnect,
}

/// A connection to a remote device
pub struct DeviceConnection {
    pub device_id: String,
    pub device_name: String,
    pub address: SocketAddr,
    pub state: ConnectionState,
    command_tx: mpsc::Sender<ConnectionCommand>,
}

impl DeviceConnection {
    pub async fn send(&self, message: Message) -> Result<(), ConnectionError> {
        self.command_tx
            .send(ConnectionCommand::Send(message))
            .await
            .map_err(|_| ConnectionError::ChannelClosed)
    }

    pub async fn disconnect(&self) -> Result<(), ConnectionError> {
        self.command_tx
            .send(ConnectionCommand::Disconnect)
            .await
            .map_err(|_| ConnectionError::ChannelClosed)
    }
}

/// Connection manager
pub struct ConnectionManager {
    identity: Identity,
    connections: Arc<RwLock<HashMap<String, DeviceConnection>>>,
    paired_devices: Arc<RwLock<HashMap<String, PairingInfo>>>,
    event_tx: broadcast::Sender<ConnectionEvent>,
}

impl ConnectionManager {
    pub fn new(identity: Identity) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        Self {
            identity,
            connections: Arc::new(RwLock::new(HashMap::new())),
            paired_devices: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    pub async fn load_paired_devices(&self, devices: Vec<PairingInfo>) {
        let mut paired = self.paired_devices.write().await;
        for device in devices {
            paired.insert(device.device_id.clone(), device);
        }
    }

    pub async fn get_paired_devices(&self) -> Vec<PairingInfo> {
        self.paired_devices.read().await.values().cloned().collect()
    }

    pub async fn start_listener(&self) -> Result<(), ConnectionError> {
        let listener = TcpListener::bind(("0.0.0.0", TCP_PORT)).await?;
        info!("Listening for connections on port {}", TCP_PORT);

        let identity = self.identity.clone();
        let connections = self.connections.clone();
        let paired_devices = self.paired_devices.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Incoming connection from {}", addr);
                        let identity = identity.clone();
                        let connections = connections.clone();
                        let paired_devices = paired_devices.clone();
                        let event_tx = event_tx.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream,
                                addr,
                                identity,
                                connections,
                                paired_devices,
                                event_tx,
                                false,
                            )
                            .await
                            {
                                error!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<(), ConnectionError> {
        info!("Connecting to {}", addr);

        let stream = timeout(
            Duration::from_secs(CONNECTION_TIMEOUT_SECS),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| ConnectionError::Timeout)?
        .map_err(ConnectionError::Io)?;

        let identity = self.identity.clone();
        let connections = self.connections.clone();
        let paired_devices = self.paired_devices.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                addr,
                identity,
                connections,
                paired_devices,
                event_tx,
                true,
            )
            .await
            {
                error!("Connection error to {}: {}", addr, e);
            }
        });

        Ok(())
    }

    pub async fn send_to(&self, device_id: &str, message: Message) -> Result<(), ConnectionError> {
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(device_id) {
            info!("Sending {:?} to {}", message.message_type(), device_id);
            conn.send(message).await
        } else {
            warn!("Cannot send to {}: not connected", device_id);
            Err(ConnectionError::NotConnected)
        }
    }

    pub async fn broadcast(&self, message: Message) -> Result<(), ConnectionError> {
        let connections = self.connections.read().await;
        let msg_type = message.message_type();
        for (device_id, conn) in connections.iter() {
            debug!("Broadcasting {:?} to {}", msg_type, device_id);
            if let Err(e) = conn.send(message.clone()).await {
                warn!("Failed to broadcast to {}: {}", device_id, e);
            }
        }
        Ok(())
    }

    pub async fn connected_devices(&self) -> Vec<String> {
        self.connections.read().await.keys().cloned().collect()
    }

    pub async fn disconnect(&self, device_id: &str) -> Result<(), ConnectionError> {
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(device_id) {
            conn.disconnect().await
        } else {
            Err(ConnectionError::NotConnected)
        }
    }

    pub async fn request_pairing(&self, device_id: &str) -> Result<(), ConnectionError> {
        info!("Requesting pairing with device: {}", device_id);

        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(device_id) {
            let key_pair = KeyPair::generate();
            conn.command_tx
                .send(ConnectionCommand::RequestPairing(key_pair))
                .await
                .map_err(|_| ConnectionError::Protocol("Failed to send command".into()))?;
            Ok(())
        } else {
            warn!("Device {} not in connections map", device_id);
            Err(ConnectionError::NotConnected)
        }
    }
}

/// Handle a connection (both incoming and outgoing)
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    our_identity: Identity,
    connections: Arc<RwLock<HashMap<String, DeviceConnection>>>,
    paired_devices: Arc<RwLock<HashMap<String, PairingInfo>>>,
    event_tx: broadcast::Sender<ConnectionEvent>,
    _is_outgoing: bool,
) -> Result<(), ConnectionError> {
    let (mut reader, mut writer) = stream.into_split();
    let (command_tx, mut command_rx) = mpsc::channel::<ConnectionCommand>(32);

    // Send our identity
    let mut identity_msg = our_identity.clone();
    identity_msg.session_nonce = Some(generate_session_nonce().to_vec());

    let encoded = Message::Identity(identity_msg.clone()).encode(MessageFlags::default())?;
    writer.write_all(&encoded).await?;

    // Read peer's identity
    let mut header = [0u8; 8];
    timeout(
        Duration::from_secs(CONNECTION_TIMEOUT_SECS),
        reader.read_exact(&mut header),
    )
    .await
    .map_err(|_| ConnectionError::Timeout)??;

    if header[0..2] != MAGIC {
        return Err(ConnectionError::Protocol("Invalid magic".to_string()));
    }

    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > MAX_MESSAGE_SIZE {
        return Err(ConnectionError::Protocol("Message too large".to_string()));
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    let peer_identity: Identity = rmp_serde::from_slice(&payload)?;

    info!(
        "Connected to {} ({}) at {}",
        peer_identity.name, peer_identity.device_id, addr
    );

    let device_id = peer_identity.device_id.clone();
    let device_name = peer_identity.name.clone();

    // Create connection entry
    let connection = DeviceConnection {
        device_id: device_id.clone(),
        device_name: device_name.clone(),
        address: addr,
        state: ConnectionState::Identified,
        command_tx: command_tx.clone(),
    };

    {
        let mut conns = connections.write().await;
        conns.insert(device_id.clone(), connection);
    }

    // Notify of connection
    let _ = event_tx.send(ConnectionEvent::Connected {
        device_id: device_id.clone(),
        device_name: device_name.clone(),
        address: addr,
    });

    let _ = event_tx.send(ConnectionEvent::Identified {
        device_id: device_id.clone(),
        identity: peer_identity.clone(),
    });

    // Pairing state
    let mut pairing_key_pair: Option<KeyPair> = None;
    let mut peer_public_key: Option<[u8; PUBLIC_KEY_SIZE]> = None;

    // Main connection loop
    loop {
        tokio::select! {
            result = read_message(&mut reader) => {
                match result {
                    Ok((message, _flags)) => {
                        match &message {
                            Message::PairRequest(req) => {
                                if req.public_key.len() == PUBLIC_KEY_SIZE {
                                    let mut key = [0u8; PUBLIC_KEY_SIZE];
                                    key.copy_from_slice(&req.public_key);
                                    peer_public_key = Some(key);

                                    let kp = KeyPair::generate();
                                    pairing_key_pair = Some(kp);

                                    let _ = event_tx.send(ConnectionEvent::PairingRequested {
                                        device_id: device_id.clone(),
                                        device_name: device_name.clone(),
                                        verification_code: "------".to_string(),
                                    });
                                }
                            }
                            Message::PairResponse(resp) => {
                                if resp.accepted {
                                    if let (Some(peer_key_bytes), Some(kp)) = (resp.public_key.as_ref(), pairing_key_pair.take()) {
                                        if peer_key_bytes.len() == PUBLIC_KEY_SIZE {
                                            let mut peer_key = [0u8; PUBLIC_KEY_SIZE];
                                            peer_key.copy_from_slice(peer_key_bytes);

                                            let shared = kp.key_exchange(&peer_key);
                                            let pairing_key = derive_pairing_key(shared.as_bytes());
                                            let code = generate_verification_code(shared.as_bytes());
                                            info!("Pairing accepted! Verification code: {}", code);

                                            let pairing_info = PairingInfo {
                                                device_id: device_id.clone(),
                                                device_name: device_name.clone(),
                                                pairing_key,
                                                paired_at: std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_secs(),
                                            };

                                            {
                                                let mut paired = paired_devices.write().await;
                                                paired.insert(device_id.clone(), pairing_info);
                                            }

                                            let _ = event_tx.send(ConnectionEvent::Paired {
                                                device_id: device_id.clone(),
                                                device_name: device_name.clone(),
                                            });
                                        }
                                    }
                                } else {
                                    let _ = event_tx.send(ConnectionEvent::PairingRejected {
                                        device_id: device_id.clone(),
                                        reason: resp.reason.clone().unwrap_or_default(),
                                    });
                                }
                            }
                            Message::Disconnect(disc) => {
                                let _ = event_tx.send(ConnectionEvent::Disconnected {
                                    device_id: device_id.clone(),
                                    reason: disc.reason.clone(),
                                });
                                break;
                            }
                            _ => {
                                let _ = event_tx.send(ConnectionEvent::MessageReceived {
                                    device_id: device_id.clone(),
                                    message,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Read error: {}", e);
                        break;
                    }
                }
            }

            Some(cmd) = command_rx.recv() => {
                match cmd {
                    ConnectionCommand::Send(message) => {
                        let flags = MessageFlags::default();
                        match message.encode(flags) {
                            Ok(data) => {
                                if let Err(e) = writer.write_all(&data).await {
                                    error!("Write error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Encode error: {}", e);
                            }
                        }
                    }
                    ConnectionCommand::RequestPairing(key_pair) => {
                        info!("Initiating pairing with {}", device_id);
                        let public_key = key_pair.public_key_bytes().to_vec();
                        pairing_key_pair = Some(key_pair);

                        let request = Message::PairRequest(PairRequest {
                            msg_type: MessageType::PairRequest,
                            device_id: our_identity.device_id.clone(),
                            name: our_identity.name.clone(),
                            public_key,
                        });

                        if let Ok(data) = request.encode(MessageFlags::default()) {
                            if let Err(e) = writer.write_all(&data).await {
                                error!("Failed to send PairRequest: {}", e);
                            }
                        }
                    }
                    ConnectionCommand::AcceptPairing => {
                        if let Some(kp) = pairing_key_pair.take() {
                            let response = Message::PairResponse(PairResponse {
                                msg_type: MessageType::PairResponse,
                                accepted: true,
                                public_key: Some(serde_bytes::ByteBuf::from(kp.public_key_bytes().to_vec())),
                                reason: None,
                            });

                            if let Some(peer_key) = peer_public_key.take() {
                                let shared = kp.key_exchange(&peer_key);
                                let pairing_key = derive_pairing_key(shared.as_bytes());

                                let pairing_info = PairingInfo {
                                    device_id: device_id.clone(),
                                    device_name: device_name.clone(),
                                    pairing_key,
                                    paired_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                };

                                {
                                    let mut paired = paired_devices.write().await;
                                    paired.insert(device_id.clone(), pairing_info);
                                }

                                let _ = event_tx.send(ConnectionEvent::Paired {
                                    device_id: device_id.clone(),
                                    device_name: device_name.clone(),
                                });
                            }

                            if let Ok(data) = response.encode(MessageFlags::default()) {
                                let _ = writer.write_all(&data).await;
                            }
                        }
                    }
                    ConnectionCommand::RejectPairing => {
                        let response = Message::PairResponse(PairResponse {
                            msg_type: MessageType::PairResponse,
                            accepted: false,
                            public_key: None,
                            reason: Some("user_rejected".to_string()),
                        });

                        if let Ok(data) = response.encode(MessageFlags::default()) {
                            let _ = writer.write_all(&data).await;
                        }
                    }
                    ConnectionCommand::Disconnect => {
                        let disconnect = Message::Disconnect(Disconnect {
                            msg_type: MessageType::Disconnect,
                            reason: Some("user_request".to_string()),
                        });

                        if let Ok(data) = disconnect.encode(MessageFlags::default()) {
                            let _ = writer.write_all(&data).await;
                        }
                        break;
                    }
                }
            }
        }
    }

    // Clean up
    {
        let mut conns = connections.write().await;
        conns.remove(&device_id);
    }

    let _ = event_tx.send(ConnectionEvent::Disconnected {
        device_id,
        reason: None,
    });

    Ok(())
}

/// Helper to extract just the type field from a message payload
#[derive(Debug, serde::Deserialize)]
struct TypeWrapper {
    #[serde(rename = "type")]
    msg_type: u8,
}

/// Read a message from the stream
async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(Message, MessageFlags), ConnectionError> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;

    if header[0..2] != MAGIC {
        return Err(ConnectionError::Protocol("Invalid magic".to_string()));
    }

    let flags = MessageFlags::from_byte(header[3]);
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    if length > MAX_MESSAGE_SIZE {
        return Err(ConnectionError::Protocol("Message too large".to_string()));
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    let type_value: TypeWrapper = rmp_serde::from_slice(&payload)?;
    let msg_type = MessageType::try_from(type_value.msg_type)
        .map_err(|e| ConnectionError::Protocol(e.to_string()))?;

    let message = match msg_type {
        MessageType::Identity => Message::Identity(rmp_serde::from_slice(&payload)?),
        MessageType::PairRequest => Message::PairRequest(rmp_serde::from_slice(&payload)?),
        MessageType::PairResponse => Message::PairResponse(rmp_serde::from_slice(&payload)?),
        MessageType::Ping => Message::Ping(rmp_serde::from_slice(&payload)?),
        MessageType::Pong => Message::Pong(rmp_serde::from_slice(&payload)?),
        MessageType::Clipboard => Message::Clipboard(rmp_serde::from_slice(&payload)?),
        MessageType::Notification => Message::Notification(rmp_serde::from_slice(&payload)?),
        MessageType::NotificationAction => Message::NotificationAction(rmp_serde::from_slice(&payload)?),
        MessageType::FileOffer => Message::FileOffer(rmp_serde::from_slice(&payload)?),
        MessageType::FindDevice => Message::FindDevice(rmp_serde::from_slice(&payload)?),
        MessageType::ShareUrl => Message::ShareUrl(rmp_serde::from_slice(&payload)?),
        MessageType::ShareText => Message::ShareText(rmp_serde::from_slice(&payload)?),
        MessageType::Disconnect => Message::Disconnect(rmp_serde::from_slice(&payload)?),
        _ => return Err(ConnectionError::Protocol(format!("Unhandled message type: {:?}", msg_type))),
    };

    Ok((message, flags))
}

/// Connection errors
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Not connected")]
    NotConnected,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Message error: {0}")]
    Message(#[from] MessageError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),
}
