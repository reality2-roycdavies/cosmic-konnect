//! CKP Message types and serialization

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
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

/// Pairing confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairConfirm {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub proof: Vec<u8>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

/// Accept file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccept {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub transfer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<usize>,
}

/// Reject file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReject {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub transfer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// File data chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub transfer_id: String,
    pub offset: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// File transfer complete
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplete {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub transfer_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
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

/// Media control action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaAction {
    Play,
    Pause,
    Next,
    Previous,
    Volume,
}

/// Media control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaControl {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub action: MediaAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u8>,
}

/// Media info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInfo {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub album: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
    pub playing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artwork: Option<Vec<u8>>,
}

/// Remote input type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    Key,
    MouseMove,
    MouseClick,
    Scroll,
}

/// Remote input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteInput {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub input_type: InputType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default)]
    pub modifiers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dx: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dy: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button: Option<String>,
}

/// Disconnect message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disconnect {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub code: u16,
    pub message: String,
}

/// Helper to extract just the type field from a message
#[derive(Debug, Deserialize)]
struct TypeWrapper {
    #[serde(rename = "type")]
    msg_type: u8,
}

/// All possible messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Identity(Identity),
    PairRequest(PairRequest),
    PairResponse(PairResponse),
    PairConfirm(PairConfirm),
    Ping(Ping),
    Pong(Pong),
    Clipboard(Clipboard),
    Notification(Notification),
    NotificationAction(NotificationAction),
    FileOffer(FileOffer),
    FileAccept(FileAccept),
    FileReject(FileReject),
    FileChunk(FileChunk),
    FileComplete(FileComplete),
    FindDevice(FindDevice),
    ShareUrl(ShareUrl),
    ShareText(ShareText),
    MediaControl(MediaControl),
    MediaInfo(MediaInfo),
    RemoteInput(RemoteInput),
    Disconnect(Disconnect),
    Error(ErrorMessage),
}

impl Message {
    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Identity(_) => MessageType::Identity,
            Self::PairRequest(_) => MessageType::PairRequest,
            Self::PairResponse(_) => MessageType::PairResponse,
            Self::PairConfirm(_) => MessageType::PairConfirm,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::Clipboard(_) => MessageType::Clipboard,
            Self::Notification(_) => MessageType::Notification,
            Self::NotificationAction(_) => MessageType::NotificationAction,
            Self::FileOffer(_) => MessageType::FileOffer,
            Self::FileAccept(_) => MessageType::FileAccept,
            Self::FileReject(_) => MessageType::FileReject,
            Self::FileChunk(_) => MessageType::FileChunk,
            Self::FileComplete(_) => MessageType::FileComplete,
            Self::FindDevice(_) => MessageType::FindDevice,
            Self::ShareUrl(_) => MessageType::ShareUrl,
            Self::ShareText(_) => MessageType::ShareText,
            Self::MediaControl(_) => MessageType::MediaControl,
            Self::MediaInfo(_) => MessageType::MediaInfo,
            Self::RemoteInput(_) => MessageType::RemoteInput,
            Self::Disconnect(_) => MessageType::Disconnect,
            Self::Error(_) => MessageType::ErrorMsg,
        }
    }

    /// Encode message to bytes with header
    pub fn encode(&self, flags: MessageFlags) -> Result<Vec<u8>, MessageError> {
        // Serialize the inner struct directly, not the enum wrapper
        // This produces {type: ..., field: ...} instead of {"Identity": {...}}
        let payload = match self {
            Self::Identity(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::PairRequest(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::PairResponse(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::PairConfirm(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Ping(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Pong(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Clipboard(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Notification(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::NotificationAction(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileOffer(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileAccept(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileReject(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileChunk(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FileComplete(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::FindDevice(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::ShareUrl(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::ShareText(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::MediaControl(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::MediaInfo(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::RemoteInput(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Disconnect(msg) => rmp_serde::encode::to_vec_named(msg)?,
            Self::Error(msg) => rmp_serde::encode::to_vec_named(msg)?,
        };

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(payload.len()));
        }

        let mut buffer = Vec::with_capacity(8 + payload.len());

        // Header
        buffer.extend_from_slice(&MAGIC);
        buffer.push(PROTOCOL_VERSION);
        buffer.push(flags.to_byte());

        // Length (big-endian u32)
        buffer.extend_from_slice(&(payload.len() as u32).to_be_bytes());

        // Payload
        buffer.extend_from_slice(&payload);

        Ok(buffer)
    }

    /// Decode message from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, MessageFlags), MessageError> {
        if data.len() < 8 {
            return Err(MessageError::InvalidHeader);
        }

        // Verify magic
        if data[0..2] != MAGIC {
            return Err(MessageError::InvalidMagic);
        }

        // Check version
        let version = data[2];
        if version > PROTOCOL_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }

        let flags = MessageFlags::from_byte(data[3]);

        // Get length
        let length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(length));
        }

        if data.len() < 8 + length {
            return Err(MessageError::IncompleteMessage);
        }

        let payload = &data[8..8 + length];

        // First, extract the type field from the payload
        // The payload is a MessagePack map with a "type" field containing the message type byte
        let type_value: TypeWrapper = rmp_serde::from_slice(payload)?;
        let msg_type = MessageType::try_from(type_value.msg_type)?;

        // Now deserialize the correct message type
        let message = match msg_type {
            MessageType::Identity => Message::Identity(rmp_serde::from_slice(payload)?),
            MessageType::PairRequest => Message::PairRequest(rmp_serde::from_slice(payload)?),
            MessageType::PairResponse => Message::PairResponse(rmp_serde::from_slice(payload)?),
            MessageType::PairConfirm => Message::PairConfirm(rmp_serde::from_slice(payload)?),
            MessageType::Ping => Message::Ping(rmp_serde::from_slice(payload)?),
            MessageType::Pong => Message::Pong(rmp_serde::from_slice(payload)?),
            MessageType::Clipboard => Message::Clipboard(rmp_serde::from_slice(payload)?),
            MessageType::Notification => Message::Notification(rmp_serde::from_slice(payload)?),
            MessageType::NotificationAction => Message::NotificationAction(rmp_serde::from_slice(payload)?),
            MessageType::FileOffer => Message::FileOffer(rmp_serde::from_slice(payload)?),
            MessageType::FileAccept => Message::FileAccept(rmp_serde::from_slice(payload)?),
            MessageType::FileReject => Message::FileReject(rmp_serde::from_slice(payload)?),
            MessageType::FileChunk => Message::FileChunk(rmp_serde::from_slice(payload)?),
            MessageType::FileComplete => Message::FileComplete(rmp_serde::from_slice(payload)?),
            MessageType::FindDevice => Message::FindDevice(rmp_serde::from_slice(payload)?),
            MessageType::ShareUrl => Message::ShareUrl(rmp_serde::from_slice(payload)?),
            MessageType::ShareText => Message::ShareText(rmp_serde::from_slice(payload)?),
            MessageType::MediaControl => Message::MediaControl(rmp_serde::from_slice(payload)?),
            MessageType::MediaInfo => Message::MediaInfo(rmp_serde::from_slice(payload)?),
            MessageType::RemoteInput => Message::RemoteInput(rmp_serde::from_slice(payload)?),
            MessageType::Disconnect => Message::Disconnect(rmp_serde::from_slice(payload)?),
            MessageType::ErrorMsg => Message::Error(rmp_serde::from_slice(payload)?),
        };

        Ok((message, flags))
    }

    /// Read a message from a reader
    pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, MessageFlags), MessageError> {
        let mut header = [0u8; 8];
        reader.read_exact(&mut header)?;

        if header[0..2] != MAGIC {
            return Err(MessageError::InvalidMagic);
        }

        let version = header[2];
        if version > PROTOCOL_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }

        let flags = MessageFlags::from_byte(header[3]);
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(length));
        }

        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload)?;

        // Decode using type-based dispatch, same as decode()
        let type_value: TypeWrapper = rmp_serde::from_slice(&payload)?;
        let msg_type = MessageType::try_from(type_value.msg_type)?;

        let message = match msg_type {
            MessageType::Identity => Message::Identity(rmp_serde::from_slice(&payload)?),
            MessageType::PairRequest => Message::PairRequest(rmp_serde::from_slice(&payload)?),
            MessageType::PairResponse => Message::PairResponse(rmp_serde::from_slice(&payload)?),
            MessageType::PairConfirm => Message::PairConfirm(rmp_serde::from_slice(&payload)?),
            MessageType::Ping => Message::Ping(rmp_serde::from_slice(&payload)?),
            MessageType::Pong => Message::Pong(rmp_serde::from_slice(&payload)?),
            MessageType::Clipboard => Message::Clipboard(rmp_serde::from_slice(&payload)?),
            MessageType::Notification => Message::Notification(rmp_serde::from_slice(&payload)?),
            MessageType::NotificationAction => Message::NotificationAction(rmp_serde::from_slice(&payload)?),
            MessageType::FileOffer => Message::FileOffer(rmp_serde::from_slice(&payload)?),
            MessageType::FileAccept => Message::FileAccept(rmp_serde::from_slice(&payload)?),
            MessageType::FileReject => Message::FileReject(rmp_serde::from_slice(&payload)?),
            MessageType::FileChunk => Message::FileChunk(rmp_serde::from_slice(&payload)?),
            MessageType::FileComplete => Message::FileComplete(rmp_serde::from_slice(&payload)?),
            MessageType::FindDevice => Message::FindDevice(rmp_serde::from_slice(&payload)?),
            MessageType::ShareUrl => Message::ShareUrl(rmp_serde::from_slice(&payload)?),
            MessageType::ShareText => Message::ShareText(rmp_serde::from_slice(&payload)?),
            MessageType::MediaControl => Message::MediaControl(rmp_serde::from_slice(&payload)?),
            MessageType::MediaInfo => Message::MediaInfo(rmp_serde::from_slice(&payload)?),
            MessageType::RemoteInput => Message::RemoteInput(rmp_serde::from_slice(&payload)?),
            MessageType::Disconnect => Message::Disconnect(rmp_serde::from_slice(&payload)?),
            MessageType::ErrorMsg => Message::Error(rmp_serde::from_slice(&payload)?),
        };

        Ok((message, flags))
    }

    /// Write a message to a writer
    pub fn write_to<W: Write>(&self, writer: &mut W, flags: MessageFlags) -> Result<(), MessageError> {
        let data = self.encode(flags)?;
        writer.write_all(&data)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let identity = Identity::new(
            "test-device".to_string(),
            "Test Device".to_string(),
            DeviceType::Desktop,
            17161,
        );

        let msg = Message::Identity(identity);
        let encoded = msg.encode(MessageFlags::default()).unwrap();
        let (decoded, _) = Message::decode(&encoded).unwrap();

        if let Message::Identity(id) = decoded {
            assert_eq!(id.device_id, "test-device");
            assert_eq!(id.name, "Test Device");
        } else {
            panic!("Expected Identity message");
        }
    }

    #[test]
    fn test_flags() {
        let flags = MessageFlags {
            encrypted: true,
            compressed: false,
            response: true,
            error: false,
        };

        let byte = flags.to_byte();
        let decoded = MessageFlags::from_byte(byte);

        assert_eq!(flags.encrypted, decoded.encrypted);
        assert_eq!(flags.compressed, decoded.compressed);
        assert_eq!(flags.response, decoded.response);
        assert_eq!(flags.error, decoded.error);
    }
}
