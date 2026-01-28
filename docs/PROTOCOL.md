# Cosmic Konnect Protocol Specification

**Version:** 1.0
**Status:** Draft

## Overview

Cosmic Konnect Protocol (CKP) is a lightweight, secure protocol for device-to-device communication between COSMIC desktop and mobile devices. It prioritizes simplicity, efficiency, and security.

## Design Principles

1. **Binary-first**: Use MessagePack for efficient serialization
2. **Transport-agnostic**: Works over TCP, BLE GATT, and Wi-Fi Direct
3. **Secure by default**: All connections encrypted after pairing
4. **Minimal handshake**: Fast connection establishment
5. **Extensible**: Version-aware message format

---

## Message Format

All messages use MessagePack encoding with the following structure:

```
┌─────────────────────────────────────────────────────┐
│ Header (4 bytes)                                    │
├─────────────────────────────────────────────────────┤
│ Magic (2 bytes): 0xCK (0x43 0x4B)                  │
│ Version (1 byte): Protocol version (currently 1)   │
│ Flags (1 byte): Message flags                      │
├─────────────────────────────────────────────────────┤
│ Length (4 bytes): Payload length (big-endian u32)  │
├─────────────────────────────────────────────────────┤
│ Payload (variable): MessagePack-encoded data       │
└─────────────────────────────────────────────────────┘
```

### Flags

| Bit | Name       | Description                          |
|-----|------------|--------------------------------------|
| 0   | Encrypted  | Payload is encrypted                 |
| 1   | Compressed | Payload is LZ4 compressed            |
| 2   | Response   | This is a response to a request      |
| 3   | Error      | This message indicates an error      |
| 4-7 | Reserved   | For future use                       |

---

## Message Types

Each payload contains a `type` field identifying the message:

| Type | Name              | Description                        |
|------|-------------------|------------------------------------|
| 0x01 | Identity          | Device identification              |
| 0x02 | Pair Request      | Initiate pairing                   |
| 0x03 | Pair Response     | Accept/reject pairing              |
| 0x04 | Pair Confirm      | Confirm shared key                 |
| 0x10 | Ping              | Presence check / notification      |
| 0x11 | Pong              | Response to ping                   |
| 0x20 | Clipboard         | Clipboard content sync             |
| 0x30 | Notification      | Phone notification                 |
| 0x31 | NotificationAction| Action on notification             |
| 0x40 | FileOffer         | Offer to send file                 |
| 0x41 | FileAccept        | Accept file transfer               |
| 0x42 | FileReject        | Reject file transfer               |
| 0x43 | FileChunk         | File data chunk                    |
| 0x44 | FileComplete      | File transfer complete             |
| 0x50 | FindDevice        | Ring the target device             |
| 0x60 | ShareUrl          | Share a URL                        |
| 0x61 | ShareText         | Share text content                 |
| 0x70 | MediaControl      | Control media playback             |
| 0x71 | MediaInfo         | Current media information          |
| 0x80 | RemoteInput       | Keyboard/mouse input               |
| 0xF0 | Disconnect        | Graceful disconnect                |
| 0xFF | Error             | Error message                      |

---

## Discovery

### UDP Broadcast Discovery

- **Port:** 17160
- **Broadcast interval:** 5 seconds while discovering
- **Multicast group:** 224.0.0.167 (optional, for routed networks)

Discovery packet (unencrypted, MessagePack):

```
{
  "type": 1,              // Identity
  "device_id": "uuid",    // Unique device identifier
  "name": "Device Name",  // Human-readable name
  "device_type": "desktop"|"phone"|"tablet"|"tv",
  "protocol_version": 1,
  "tcp_port": 17161,      // Port for TCP connections
  "capabilities": ["clipboard", "files", "notifications", ...]
}
```

### BLE Discovery

**Service UUID:** `c05a1c00-a0aa-3c70-9000-000000000001`

**Characteristics:**

| UUID | Name | Properties | Description |
|------|------|------------|-------------|
| `...9001...` | Identity | Read, Notify | Device identity (MessagePack) |
| `...9002...` | Message | Write, Notify | Bidirectional messages |
| `...9003...` | ConnectionInfo | Read | IP address and TCP port |

Identity characteristic contains:
```
{
  "device_id": "uuid",
  "name": "Device Name",
  "device_type": "phone",
  "protocol_version": 1,
  "tcp_port": 17161
}
```

ConnectionInfo characteristic contains:
```
{
  "addresses": ["192.168.1.100", "10.0.0.5"],
  "port": 17161
}
```

### Wi-Fi Direct Discovery

**Service Type:** `_cosmickonnect._tcp`

**TXT Records:**
- `id`: Device ID
- `name`: Device name
- `type`: Device type
- `port`: TCP port
- `ver`: Protocol version

---

## Connection Establishment

### TCP Connection

1. Client connects to device's TCP port (default 17161)
2. Client sends Identity message
3. Server responds with Identity message
4. If devices are paired, both switch to encrypted mode
5. If not paired, pairing handshake begins (or connection closes)

### Connection States

```
┌──────────┐    Identity    ┌────────────┐
│Connected │───────────────▶│ Identified │
└──────────┘                └────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
              (Not Paired)                   (Paired)
                    │                             │
                    ▼                             ▼
            ┌──────────────┐             ┌──────────────┐
            │   Pairing    │             │  Encrypted   │
            └──────────────┘             └──────────────┘
                    │                             │
                    │ (Success)                   │
                    └─────────────────────────────┘
```

---

## Pairing

Cosmic Konnect uses a simple, secure pairing mechanism based on ECDH key exchange with visual verification.

### Pairing Flow

```
Device A                              Device B
   │                                      │
   │──────── PairRequest ────────────────▶│
   │         (A's public key)             │
   │                                      │
   │◀─────── PairResponse ────────────────│
   │         (B's public key, accepted)   │
   │                                      │
   │  [Both compute shared secret]        │
   │  [Both display verification code]    │
   │                                      │
   │  [User confirms code matches]        │
   │                                      │
   │──────── PairConfirm ────────────────▶│
   │         (encrypted with shared key)  │
   │                                      │
   │◀─────── PairConfirm ─────────────────│
   │         (encrypted with shared key)  │
   │                                      │
   │  [Pairing complete - keys stored]    │
```

### Key Generation

- **Algorithm:** X25519 for key exchange
- **Verification code:** First 6 digits of SHA-256(shared_secret)
- **Encryption key:** HKDF-SHA256(shared_secret, "cosmic-konnect-v1")

### Pair Request Message

```
{
  "type": 2,
  "device_id": "uuid",
  "name": "Device Name",
  "public_key": <32 bytes X25519 public key>
}
```

### Pair Response Message

```
{
  "type": 3,
  "accepted": true|false,
  "public_key": <32 bytes X25519 public key>,  // if accepted
  "reason": "user_rejected"|"already_paired"|...  // if rejected
}
```

### Pair Confirm Message

```
{
  "type": 4,
  "proof": <encrypted nonce with derived key>
}
```

---

## Encryption

After pairing, all messages are encrypted using ChaCha20-Poly1305.

### Session Key Derivation

For each session:
1. Exchange random 32-byte nonces in Identity messages
2. Derive session key: `HKDF-SHA256(pairing_key, nonce_a || nonce_b, "session")`

### Encrypted Payload Format

```
┌─────────────────────────────────────┐
│ Nonce (12 bytes)                    │
├─────────────────────────────────────┤
│ Ciphertext (variable)               │
├─────────────────────────────────────┤
│ Auth Tag (16 bytes)                 │
└─────────────────────────────────────┘
```

---

## Feature Messages

### Ping (0x10)

```
{
  "type": 16,
  "message": "Optional message"  // optional
}
```

### Pong (0x11)

```
{
  "type": 17
}
```

### Clipboard (0x20)

```
{
  "type": 32,
  "content": "clipboard text",
  "timestamp": 1234567890123  // ms since epoch
}
```

### Notification (0x30)

```
{
  "type": 48,
  "id": "notification-id",
  "app": "App Name",
  "title": "Notification Title",
  "text": "Notification body",
  "icon": <binary PNG data>,  // optional
  "actions": ["Reply", "Dismiss"],  // optional
  "timestamp": 1234567890123,
  "dismissable": true,
  "silent": false
}
```

### Notification Action (0x31)

```
{
  "type": 49,
  "id": "notification-id",
  "action": "dismiss"|"reply"|<action name>,
  "reply_text": "Reply content"  // if action is "reply"
}
```

### File Offer (0x40)

```
{
  "type": 64,
  "transfer_id": "uuid",
  "filename": "document.pdf",
  "size": 1048576,
  "mime_type": "application/pdf",
  "checksum": "sha256:abc123..."  // optional
}
```

### File Accept (0x41)

```
{
  "type": 65,
  "transfer_id": "uuid"
}
```

### File Reject (0x42)

```
{
  "type": 66,
  "transfer_id": "uuid",
  "reason": "user_rejected"|"no_space"|...
}
```

### File Chunk (0x43)

```
{
  "type": 67,
  "transfer_id": "uuid",
  "offset": 0,
  "data": <binary chunk data>
}
```

Chunk size: 64KB default (configurable during File Accept)

### File Complete (0x44)

```
{
  "type": 68,
  "transfer_id": "uuid",
  "success": true,
  "checksum": "sha256:abc123..."  // for verification
}
```

### Find Device (0x50)

```
{
  "type": 80
}
```

Target device should ring/vibrate for attention.

### Share URL (0x60)

```
{
  "type": 96,
  "url": "https://example.com/page"
}
```

### Share Text (0x61)

```
{
  "type": 97,
  "text": "Shared text content"
}
```

### Media Control (0x70)

```
{
  "type": 112,
  "action": "play"|"pause"|"next"|"previous"|"volume",
  "value": 75  // for volume (0-100)
}
```

### Media Info (0x71)

```
{
  "type": 113,
  "title": "Song Title",
  "artist": "Artist Name",
  "album": "Album Name",
  "duration": 240000,  // ms
  "position": 60000,   // ms
  "playing": true,
  "artwork": <binary PNG/JPEG>  // optional
}
```

### Remote Input (0x80)

```
{
  "type": 128,
  "input_type": "key"|"mouse_move"|"mouse_click"|"scroll",
  "key": "a",           // for key
  "modifiers": ["ctrl"], // for key
  "dx": 10, "dy": 5,    // for mouse_move/scroll
  "button": "left"      // for mouse_click
}
```

### Disconnect (0xF0)

```
{
  "type": 240,
  "reason": "user_request"|"shutdown"|"error"
}
```

### Error (0xFF)

```
{
  "type": 255,
  "code": 1,
  "message": "Error description"
}
```

Error codes:
- 1: Unknown error
- 2: Protocol error
- 3: Not paired
- 4: Encryption error
- 5: Not supported
- 6: Rate limited

---

## Ports and Constants

| Item | Value |
|------|-------|
| UDP Discovery Port | 17160 |
| TCP Connection Port | 17161 |
| BLE Service UUID | c05a1c00-a0aa-3c70-9000-000000000001 |
| Wi-Fi Direct Service | _cosmickonnect._tcp |
| Protocol Version | 1 |
| Magic Bytes | 0x43 0x4B ("CK") |
| Max Message Size | 16 MB |
| File Chunk Size | 64 KB (default) |
| Discovery Interval | 5 seconds |
| Connection Timeout | 30 seconds |
| Keepalive Interval | 60 seconds |

---

## Security Considerations

1. **Pairing verification:** Users MUST verify the 6-digit code matches on both devices
2. **Key storage:** Pairing keys should be stored in secure storage (Keychain/Keystore)
3. **Replay protection:** Use timestamps and nonces to prevent replay attacks
4. **Rate limiting:** Limit pairing attempts to prevent brute force
5. **Transport security:** Always encrypt after pairing, even on trusted networks

---

## Compatibility

This protocol is NOT compatible with KDE Connect. Devices using Cosmic Konnect can only communicate with other Cosmic Konnect devices.

### Version Negotiation

Devices advertise their protocol version in Identity messages. The lower version is used for communication. Future versions will maintain backward compatibility within the same major version.
