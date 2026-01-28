//! TCP connection handling and TLS upgrade
//!
//! Manages connections to KDE Connect devices, including:
//! - TCP listener for incoming connections
//! - TLS upgrade after identity exchange
//! - Pairing request/response handling

use crate::crypto::{is_device_trusted, load_or_generate_credentials, save_trusted_device};
use crate::identity::StoredIdentity;
use crate::protocol::{IdentityPacketBody, NetworkPacket, DEFAULT_TCP_PORT};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

/// Map of device_id -> sender for sending packets to that device
pub type DeviceSenders = Arc<RwLock<HashMap<String, mpsc::Sender<NetworkPacket>>>>;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error("Connection closed")]
    #[allow(dead_code)]
    Closed,
}

/// Events from the connection service
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Incoming connection from a device
    IncomingConnection {
        device_id: String,
        device_name: String,
        address: SocketAddr,
    },

    /// Pairing request received
    PairRequest {
        device_id: String,
        device_name: String,
    },

    /// Pairing completed successfully
    Paired {
        device_id: String,
        device_name: String,
    },

    /// Pairing was rejected
    PairRejected {
        device_id: String,
    },

    /// Device disconnected
    Disconnected {
        device_id: String,
    },

    /// Received a packet from a device
    PacketReceived {
        device_id: String,
        packet: NetworkPacket,
    },
}

/// Pairing packet body
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairPacketBody {
    pub pair: bool,
}

/// Connection service manages TCP connections
pub struct ConnectionService {
    identity: StoredIdentity,
    tcp_port: u16,
    event_tx: broadcast::Sender<ConnectionEvent>,
    tls_config: Option<Arc<ServerConfig>>,
    /// Senders for sending packets to connected devices
    device_senders: DeviceSenders,
}

impl ConnectionService {
    /// Create a new connection service
    pub fn new(mut identity: StoredIdentity, tcp_port: u16) -> Result<Self, ConnectionError> {
        let (event_tx, _) = broadcast::channel(64);

        // Load or generate TLS credentials
        let (certs, key) = load_or_generate_credentials(&mut identity)?;

        // Build server TLS config (accepts any client certificate for pairing)
        let server_config = ServerConfig::builder()
            .with_no_client_auth() // We handle pairing at application level
            .with_single_cert(certs, key)
            .map_err(|e| ConnectionError::Tls(e.to_string()))?;

        Ok(Self {
            identity,
            tcp_port,
            event_tx,
            tls_config: Some(Arc::new(server_config)),
            device_senders: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get a clone of the device senders map (for external packet sending)
    pub fn get_device_senders(&self) -> DeviceSenders {
        self.device_senders.clone()
    }

    /// Send a packet to a specific device
    pub async fn send_packet(&self, device_id: &str, packet: NetworkPacket) -> Result<(), ConnectionError> {
        let senders = self.device_senders.read().await;
        if let Some(sender) = senders.get(device_id) {
            sender.send(packet).await.map_err(|_| {
                ConnectionError::Protocol(format!("Failed to send packet to {}", device_id))
            })
        } else {
            Err(ConnectionError::Protocol(format!("Device {} not connected", device_id)))
        }
    }

    /// Subscribe to connection events
    pub fn subscribe(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    /// Start listening for incoming connections
    pub async fn start_listener(&self) -> Result<(), ConnectionError> {
        let addr = format!("0.0.0.0:{}", self.tcp_port);
        let listener = TcpListener::bind(&addr).await?;
        info!("TCP listener started on {}", addr);

        let tls_acceptor = self
            .tls_config
            .as_ref()
            .map(|config| TlsAcceptor::from(config.clone()));

        let identity = self.identity.clone();
        let event_tx = self.event_tx.clone();
        let device_senders = self.device_senders.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Incoming connection from {}", addr);
                        let identity = identity.clone();
                        let event_tx = event_tx.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let device_senders = device_senders.clone();

                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_incoming_connection(stream, addr, identity, event_tx, tls_acceptor, device_senders).await
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

    /// Connect to a discovered device
    pub async fn connect_to(
        &self,
        addr: SocketAddr,
        their_identity: Option<IdentityPacketBody>,
    ) -> Result<(), ConnectionError> {
        info!("Connecting to {}", addr);

        let stream = TcpStream::connect(addr).await?;
        let identity = self.identity.clone();
        let event_tx = self.event_tx.clone();
        let device_senders = self.device_senders.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_outgoing_connection(stream, addr, identity, event_tx, their_identity, device_senders).await {
                error!("Outgoing connection error to {}: {}", addr, e);
            }
        });

        Ok(())
    }

    /// Get the identity packet for this device
    pub fn get_identity_packet(&self) -> IdentityPacketBody {
        IdentityPacketBody::new(
            self.identity.device_id.clone(),
            self.identity.device_name.clone(),
            self.identity.device_type,
        )
        .with_tcp_port(self.tcp_port)
        .with_capabilities(
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
            vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
            ],
        )
    }
}

/// Handle an incoming TCP connection
/// KDE Connect protocol: TCP server becomes TLS CLIENT (inverted roles)
async fn handle_incoming_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    our_identity: StoredIdentity,
    event_tx: broadcast::Sender<ConnectionEvent>,
    _tls_acceptor: Option<TlsAcceptor>, // Not used - we're TLS client for incoming
    device_senders: DeviceSenders,
) -> Result<(), ConnectionError> {
    // First, receive their identity packet (unencrypted)
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();

    // Set timeout for identity read
    let read_result = tokio::time::timeout(
        Duration::from_secs(5),
        reader.read_line(&mut line)
    ).await;

    let bytes_read = match read_result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ConnectionError::Io(e)),
        Err(_) => return Err(ConnectionError::Protocol("Timeout waiting for identity".to_string())),
    };

    if bytes_read == 0 {
        return Err(ConnectionError::Protocol("Connection closed before identity".to_string()));
    }

    let packet = NetworkPacket::from_json(&line)?;
    if packet.packet_type != "kdeconnect.identity" {
        return Err(ConnectionError::Protocol(format!(
            "Expected identity packet, got: {}",
            packet.packet_type
        )));
    }

    let their_identity: IdentityPacketBody = serde_json::from_value(packet.body)?;
    info!(
        "Received identity from {}: {} ({})",
        addr, their_identity.device_name, their_identity.device_id
    );

    // Send our identity (plaintext, before TLS)
    let our_identity_packet = IdentityPacketBody::new(
        our_identity.device_id.clone(),
        our_identity.device_name.clone(),
        our_identity.device_type,
    )
    .with_tcp_port(DEFAULT_TCP_PORT)
    .with_capabilities(
        vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
                "kdeconnect.findmyphone.request".to_string(),
                "kdeconnect.clipboard".to_string(),
                "kdeconnect.clipboard.connect".to_string(),
                "kdeconnect.notification".to_string(),
                "kdeconnect.notification.request".to_string(),
                "kdeconnect.share.request".to_string(),
            ],
        vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
                "kdeconnect.findmyphone.request".to_string(),
                "kdeconnect.clipboard".to_string(),
                "kdeconnect.clipboard.connect".to_string(),
                "kdeconnect.notification".to_string(),
                "kdeconnect.notification.request".to_string(),
                "kdeconnect.share.request".to_string(),
            ],
    );

    // Need to get the stream back from reader
    let stream = reader.into_inner();
    let identity_json = our_identity_packet.to_packet()?.to_json_line()?;
    stream.write_all(identity_json.as_bytes()).await?;
    stream.flush().await?;
    debug!("Sent identity to {}", addr);

    // Notify about the connection
    let _ = event_tx.send(ConnectionEvent::IncomingConnection {
        device_id: their_identity.device_id.clone(),
        device_name: their_identity.device_name.clone(),
        address: addr,
    });

    // Upgrade to TLS - WE ARE TLS CLIENT (even though we're TCP server)
    // This is KDE Connect's inverted TLS role design
    let (certs, key) = load_or_generate_credentials(&mut our_identity.clone())?;

    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
        .with_client_auth_cert(certs, key)
        .map_err(|e| ConnectionError::Tls(e.to_string()))?;

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("kdeconnect".to_string())
        .map_err(|e| ConnectionError::Tls(format!("Invalid server name: {}", e)))?;

    debug!("Upgrading to TLS as CLIENT (inverted role)...");

    let tls_result = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream)
    ).await;

    let tls_stream = match tls_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ConnectionError::Tls(format!("TLS handshake failed: {}", e))),
        Err(_) => return Err(ConnectionError::Tls("TLS handshake timeout".to_string())),
    };

    info!("TLS connection established with {}", their_identity.device_name);

    // Handle the connection
    handle_connected_device(tls_stream, their_identity, our_identity, event_tx, device_senders).await
}

/// Handle an outgoing TCP connection
/// KDE Connect protocol: TCP client becomes TLS SERVER (inverted roles)
/// We send identity, then immediately start TLS (phone starts TLS without sending identity first)
async fn handle_outgoing_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    our_identity: StoredIdentity,
    event_tx: broadcast::Sender<ConnectionEvent>,
    known_identity: Option<IdentityPacketBody>,
    device_senders: DeviceSenders,
) -> Result<(), ConnectionError> {
    info!("Connected to {}, sending identity...", addr);

    // Send our identity FIRST (plaintext, before TLS)
    let our_identity_packet = IdentityPacketBody::new(
        our_identity.device_id.clone(),
        our_identity.device_name.clone(),
        our_identity.device_type,
    )
    .with_tcp_port(DEFAULT_TCP_PORT)
    .with_capabilities(
        vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
                "kdeconnect.findmyphone.request".to_string(),
                "kdeconnect.clipboard".to_string(),
                "kdeconnect.clipboard.connect".to_string(),
                "kdeconnect.notification".to_string(),
                "kdeconnect.notification.request".to_string(),
                "kdeconnect.share.request".to_string(),
            ],
        vec![
                "kdeconnect.pair".to_string(),
                "kdeconnect.ping".to_string(),
                "kdeconnect.findmyphone.request".to_string(),
                "kdeconnect.clipboard".to_string(),
                "kdeconnect.clipboard.connect".to_string(),
                "kdeconnect.notification".to_string(),
                "kdeconnect.notification.request".to_string(),
                "kdeconnect.share.request".to_string(),
            ],
    );

    let identity_json = our_identity_packet.to_packet()?.to_json_line()?;
    stream.write_all(identity_json.as_bytes()).await?;
    stream.flush().await?;
    debug!("Sent identity (plaintext) to {}", addr);

    // Start TLS IMMEDIATELY - the phone starts TLS without sending identity first
    // We ARE TLS SERVER (even though we're TCP client) - KDE Connect's inverted role design
    let (certs, key) = load_or_generate_credentials(&mut our_identity.clone())?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ConnectionError::Tls(e.to_string()))?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    debug!("Upgrading to TLS as SERVER (inverted role)...");

    let tls_result = tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(stream)
    ).await;

    let tls_stream = match tls_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ConnectionError::Tls(format!("TLS handshake failed: {}", e))),
        Err(_) => return Err(ConnectionError::Tls("TLS handshake timeout".to_string())),
    };

    info!("TLS connection established with {}", addr);

    // Use known identity from discovery (protocol v7) or get identity from connection
    let their_identity = match known_identity {
        Some(identity) => {
            info!("Using known identity from discovery: {} ({})", identity.device_name, identity.device_id);
            identity
        }
        None => {
            // No known identity - need to establish it from the connection
            // This shouldn't happen for outgoing connections in protocol v7
            // but handle it gracefully
            return Err(ConnectionError::Protocol(
                "No identity available for connection".to_string()
            ));
        }
    };

    // Notify about connection
    let _ = event_tx.send(ConnectionEvent::IncomingConnection {
        device_id: their_identity.device_id.clone(),
        device_name: their_identity.device_name.clone(),
        address: addr,
    });

    handle_connected_device(tls_stream, their_identity, our_identity, event_tx, device_senders).await
}

/// Handle a connected device after TLS is established
async fn handle_connected_device<S>(
    stream: S,
    their_identity: IdentityPacketBody,
    _our_identity: StoredIdentity,
    event_tx: broadcast::Sender<ConnectionEvent>,
    device_senders: DeviceSenders,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let device_id = their_identity.device_id.clone();
    let device_name = their_identity.device_name.clone();

    // Create channel for sending packets to this device
    let (packet_tx, mut packet_rx) = mpsc::channel::<NetworkPacket>(32);

    // Register the sender in the shared map
    {
        let mut senders = device_senders.write().await;
        senders.insert(device_id.clone(), packet_tx);
    }

    // Check if already trusted
    let is_trusted = is_device_trusted(&device_id)?;

    if !is_trusted {
        info!("Device {} is not trusted, waiting for pairing", device_name);
    } else {
        info!("Device {} is already trusted", device_name);

        // Send a ping to test the connection
        info!("Sending ping to {}", device_name);
    }

    // Split the stream for simultaneous read/write
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // If already trusted, send a ping
    if is_trusted {
        let ping = NetworkPacket::new("kdeconnect.ping", serde_json::json!({}));
        let ping_json = ping.to_json_line()?;
        writer.write_all(ping_json.as_bytes()).await?;
        writer.flush().await?;
        info!("Ping sent to {}", device_name);
    }

    // Helper closure to clean up on disconnect
    let cleanup = || async {
        let mut senders = device_senders.write().await;
        senders.remove(&device_id);
    };

    loop {
        line.clear();

        tokio::select! {
            // Handle incoming packets from the device
            read_result = reader.read_line(&mut line) => {
                let bytes_read = match read_result {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Read error from {}: {}", device_name, e);
                        cleanup().await;
                        let _ = event_tx.send(ConnectionEvent::Disconnected {
                            device_id: device_id.clone(),
                        });
                        return Err(ConnectionError::Io(e));
                    }
                };

                if bytes_read == 0 {
                    info!("Connection closed by {}", device_name);
                    cleanup().await;
                    let _ = event_tx.send(ConnectionEvent::Disconnected {
                        device_id: device_id.clone(),
                    });
                    return Ok(());
                }

                let packet = match NetworkPacket::from_json(&line) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to parse packet: {}", e);
                        continue;
                    }
                };

                debug!("Received packet: {}", packet.packet_type);

                match packet.packet_type.as_str() {
            "kdeconnect.pair" => {
                let body: PairPacketBody = serde_json::from_value(packet.body.clone())?;

                if body.pair {
                    info!("Pairing request from {}", device_name);
                    let _ = event_tx.send(ConnectionEvent::PairRequest {
                        device_id: device_id.clone(),
                        device_name: device_name.clone(),
                    });

                    // For now, auto-accept pairing (in a real app, prompt the user)
                    info!("Auto-accepting pairing request from {}", device_name);

                    // Send pair acceptance
                    let pair_response = NetworkPacket::new(
                        "kdeconnect.pair",
                        serde_json::json!({ "pair": true }),
                    );
                    let response_json = pair_response.to_json_line()?;
                    writer.write_all(response_json.as_bytes()).await?;
                    writer.flush().await?;
                    info!("Sent pair acceptance to {}", device_name);

                    // Save as trusted
                    save_trusted_device(&device_id, "")?;

                    let _ = event_tx.send(ConnectionEvent::Paired {
                        device_id: device_id.clone(),
                        device_name: device_name.clone(),
                    });
                } else {
                    info!("Unpairing request from {}", device_name);
                    let _ = event_tx.send(ConnectionEvent::PairRejected {
                        device_id: device_id.clone(),
                    });
                }
            }

            "kdeconnect.ping" => {
                info!("Ping from {}", device_name);

                // Extract optional message from ping body
                let message = packet.body.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Ping!")
                    .to_string();

                // Show desktop notification
                let notif_name = device_name.clone();
                std::thread::spawn(move || {
                    let _ = notify_rust::Notification::new()
                        .summary(&format!("Ping from {}", notif_name))
                        .body(&message)
                        .icon("dialog-information")
                        .timeout(5000)
                        .show();
                });

                let _ = event_tx.send(ConnectionEvent::PacketReceived {
                    device_id: device_id.clone(),
                    packet,
                });
            }

            "kdeconnect.battery" => {
                if let Ok(battery) = serde_json::from_value::<serde_json::Value>(packet.body.clone()) {
                    let charge = battery.get("currentCharge").and_then(|c| c.as_i64()).unwrap_or(0);
                    let charging = battery.get("isCharging").and_then(|c| c.as_bool()).unwrap_or(false);
                    info!("Battery from {}: {}%{}", device_name, charge,
                        if charging { " (charging)" } else { "" });
                }
                let _ = event_tx.send(ConnectionEvent::PacketReceived {
                    device_id: device_id.clone(),
                    packet,
                });
            }

            _ => {
                debug!("Packet from {}: {}", device_name, packet.packet_type);
                let _ = event_tx.send(ConnectionEvent::PacketReceived {
                    device_id: device_id.clone(),
                    packet,
                });
            }
        }
            }

            // Handle outgoing packets to send to the device
            Some(packet) = packet_rx.recv() => {
                match packet.to_json_line() {
                    Ok(json) => {
                        if let Err(e) = writer.write_all(json.as_bytes()).await {
                            error!("Write error to {}: {}", device_name, e);
                            cleanup().await;
                            let _ = event_tx.send(ConnectionEvent::Disconnected {
                                device_id: device_id.clone(),
                            });
                            return Err(ConnectionError::Io(e));
                        }
                        if let Err(e) = writer.flush().await {
                            error!("Flush error to {}: {}", device_name, e);
                            cleanup().await;
                            let _ = event_tx.send(ConnectionEvent::Disconnected {
                                device_id: device_id.clone(),
                            });
                            return Err(ConnectionError::Io(e));
                        }
                        debug!("Sent packet to {}: {}", device_name, packet.packet_type);
                    }
                    Err(e) => {
                        warn!("Failed to serialize packet: {}", e);
                    }
                }
            }
        }
    }
}

/// Custom certificate verifier that accepts any certificate
/// (KDE Connect uses pairing-based trust, not CA-based)
#[derive(Debug)]
struct NoCertificateVerification;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        // Accept any certificate - we trust based on pairing, not CA
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        ]
    }
}
