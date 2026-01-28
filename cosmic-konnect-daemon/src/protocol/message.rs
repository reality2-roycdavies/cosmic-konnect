//! CKP Message types and serialization

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{MAGIC, MAX_MESSAGE_SIZE, PROTOCOL_VERSION};

/// Message header flags
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub response: bool,
    pub error: bool,
}

impl MessageFlags {
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= 0x01;
        }
        if self.compressed {
            flags |= 0x02;
        }
        if self.response {
            flags |= 0x04;
        }
        if self.error {
            flags |= 0x08;
        }
        flags
    }

    pub fn from_byte(byte: u8) -> Self {
        Self {
            encrypted: byte & 0x01 != 0,
            compressed: byte & 0x02 != 0,
            response: byte & 0x04 != 0,
            error: byte & 0x08 != 0,
        }
    }
}

/// Message type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum MessageType {
    Identity = 0x01,
    PairRequest = 0x02,
    PairResponse = 0x03,
    PairConfirm = 0x04,
    Ping = 0x10,
    Pong = 0x11,
    Clipboard = 0x20,
    Notification = 0x30,
    NotificationAction = 0x31,
    FileOffer = 0x40,
    FileAccept = 0x41,
    FileReject = 0x42,
    FileChunk = 0x43,
    FileComplete = 0x44,
    FindDevice = 0x50,
    ShareUrl = 0x60,
    ShareText = 0x61,
    MediaControl = 0x70,
    MediaInfo = 0x71,
    RemoteInput = 0x80,
    Disconnect = 0xF0,
    ErrorMsg = 0xFF,
}

impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> u8 {
        mt as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Identity),
            0x02 => Ok(Self::PairRequest),
            0x03 => Ok(Self::PairResponse),
            0x04 => Ok(Self::PairConfirm),
            0x10 => Ok(Self::Ping),
            0x11 => Ok(Self::Pong),
            0x20 => Ok(Self::Clipboard),
            0x30 => Ok(Self::Notification),
            0x31 => Ok(Self::NotificationAction),
            0x40 => Ok(Self::FileOffer),
            0x41 => Ok(Self::FileAccept),
            0x42 => Ok(Self::FileReject),
            0x43 => Ok(Self::FileChunk),
            0x44 => Ok(Self::FileComplete),
            0x50 => Ok(Self::FindDevice),
            0x60 => Ok(Self::ShareUrl),
            0x61 => Ok(Self::ShareText),
            0x70 => Ok(Self::MediaControl),
            0x71 => Ok(Self::MediaInfo),
            0x80 => Ok(Self::RemoteInput),
            0xF0 => Ok(Self::Disconnect),
            0xFF => Ok(Self::ErrorMsg),
            _ => Err(MessageError::UnknownMessageType(value)),
        }
    }
}

/// Device type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Desktop,
    Laptop,
    Phone,
    Tablet,
    Tv,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::Desktop
    }
}

/// Capabilities that a device supports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    #[serde(rename = "clipboard")]
    Clipboard,
    #[serde(rename = "files")]
    Files,
    #[serde(rename = "notifications")]
    Notifications,
    #[serde(rename = "findDevice")]
    FindDevice,
    #[serde(rename = "share")]
    Share,
    #[serde(rename = "media")]
    Media,
    #[serde(rename = "remoteInput")]
    RemoteInput,
}

/// Device identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub device_id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub protocol_version: u8,
    pub tcp_port: u16,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_nonce: Option<Vec<u8>>,
}

impl Identity {
    pub fn new(device_id: String, name: String, device_type: DeviceType, tcp_port: u16) -> Self {
        Self {
            msg_type: MessageType::Identity,
            device_id,
            name,
            device_type,
            protocol_version: PROTOCOL_VERSION,
            tcp_port,
            capabilities: vec![
                Capability::Clipboard,
                Capability::Files,
                Capability::Notifications,
                Capability::FindDevice,
                Capability::Share,
            ],
            session_nonce: None,
        }
    }
}

/// Pairing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub device_id: String,
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// Pairing response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_bytes::ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Pong response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
}

/// Clipboard content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clipboard {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub content: String,
    pub timestamp: u64,
}

/// Phone notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub id: String,
    pub app: String,
    pub title: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Vec<u8>>,
    #[serde(default)]
    pub actions: Vec<String>,
    pub timestamp: u64,
    #[serde(default = "default_true")]
    pub dismissable: bool,
    #[serde(default)]
    pub silent: bool,
}

fn default_true() -> bool {
    true
}

/// Action on a notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationAction {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_text: Option<String>,
}

/// File transfer offer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Find device (ring phone)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindDevice {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
}

/// Share URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareUrl {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub url: String,
}

/// Share text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareText {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub text: String,
}

/// Disconnect message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disconnect {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// All possible messages
#[derive(Debug, Clone)]
pub enum Message {
    Identity(Identity),
    PairRequest(PairRequest),
    PairResponse(PairResponse),
    Ping(Ping),
    Pong(Pong),
    Clipboard(Clipboard),
    Notification(Notification),
    NotificationAction(NotificationAction),
    FileOffer(FileOffer),
    FindDevice(FindDevice),
    ShareUrl(ShareUrl),
    ShareText(ShareText),
    Disconnect(Disconnect),
}

impl Message {
    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Identity(_) => MessageType::Identity,
            Self::PairRequest(_) => MessageType::PairRequest,
            Self::PairResponse(_) => MessageType::PairResponse,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::Clipboard(_) => MessageType::Clipboard,
            Self::Notification(_) => MessageType::Notification,
            Self::NotificationAction(_) => MessageType::NotificationAction,
            Self::FileOffer(_) => MessageType::FileOffer,
            Self::FindDevice(_) => MessageType::FindDevice,
            Self::ShareUrl(_) => MessageType::ShareUrl,
            Self::ShareText(_) => MessageType::ShareText,
            Self::Disconnect(_) => MessageType::Disconnect,
        }
    }

    /// Encode message to bytes with header
    pub fn encode(&self, flags: MessageFlags) -> Result<Vec<u8>, MessageError> {
        let payload = match self {
            Self::Identity(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::PairRequest(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::PairResponse(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Ping(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Pong(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Clipboard(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Notification(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::NotificationAction(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileOffer(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FindDevice(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::ShareUrl(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::ShareText(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Disconnect(msg) => rmp_serde::encode::to_vec_named(msg)?,
        };

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(payload.len()));
        }

        let mut buffer = Vec::with_capacity(8 + payload.len());
        buffer.extend_from_slice(&MAGIC);
        buffer.push(PROTOCOL_VERSION);
        buffer.push(flags.to_byte());
        buffer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&payload);

        Ok(buffer)
    }
}

/// Message errors
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Invalid message header")]
    InvalidHeader,

    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("Incomplete message")]
    IncompleteMessage,

    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
