# cosmic-konnect

KDE Connect protocol implementation for COSMIC desktop.

## Overview

cosmic-konnect implements the [KDE Connect](https://kdeconnect.kde.org/) protocol, allowing COSMIC desktop users to connect their phones, tablets, and other devices for seamless integration.

### Features

- [x] System tray icon with theme color adaptation
- [x] Device discovery (UDP broadcast/listen)
- [x] Device pairing (TLS with ECDSA certificates)
- [x] Ping plugin
- [x] Battery status (receive and display in tray)
- [ ] Clipboard synchronization
- [ ] Notification mirroring
- [ ] File transfer
- [ ] Remote input control
- [ ] Media playback control
- [ ] SMS messaging

### Compatibility

Compatible with:
- KDE Connect (Android, Linux, Windows)
- GSConnect (GNOME)
- Valent (GTK desktops)
- Zorin Connect

## Installation

### From Source

```bash
git clone https://github.com/reality2-roycdavies/cosmic-konnect.git
cd cosmic-konnect
cargo build --release
sudo cp target/release/cosmic-konnect /usr/local/bin/
```

## Usage

```bash
# Run in discovery mode (continuous)
cosmic-konnect

# Discover and pair with devices
cosmic-konnect --pair

# Scan for devices for 5 seconds
cosmic-konnect --list

# Broadcast identity once
cosmic-konnect --broadcast

# Enable verbose logging
cosmic-konnect -v
```

### Pairing with a Phone

1. Install KDE Connect on your Android phone (from Play Store or F-Droid)
2. Ensure both devices are on the same network
3. Run `cosmic-konnect --pair`
4. Accept the pairing request on your phone
5. The device will now auto-connect when on the same network

## Protocol

KDE Connect uses:
- **UDP port 1716** for device discovery (broadcast)
- **TCP port 1716** for connections
- **TLS encryption** with self-signed ECDSA certificates
- **JSON packets** for all communication

### Protocol Details

The KDE Connect protocol has some unique characteristics:

- **Inverted TLS roles**: The TCP client becomes the TLS server, and vice versa
- **Identity before TLS**: Identity packets are exchanged in plaintext, then TLS is established
- **Certificate-based pairing**: Devices trust each other by storing certificates

## Configuration

Configuration and identity are stored in:
- `~/.config/cosmic-konnect/identity.json` - Device identity and certificates
- `~/.config/cosmic-konnect/trusted_devices/` - Trusted device certificates

## System Tray

The application runs with a system tray icon that:
- Shows connection status (phone icon)
- Adapts color to COSMIC theme settings automatically
- Updates when theme changes (light/dark mode)
- Displays connected devices with battery percentage
- Provides quick access to refresh and quit

The tray icon uses the StatusNotifierItem (SNI) protocol, which is supported by:
- COSMIC desktop
- KDE Plasma
- GNOME (with AppIndicator extension)
- Most other modern Linux desktops

## Development Status

This project is in active development. Currently implemented:
- [x] Device identity generation and persistence
- [x] ECDSA certificate generation
- [x] UDP broadcast for discovery
- [x] Listening for other devices' broadcasts
- [x] Device tracking and timeout
- [x] TCP listener for incoming connections
- [x] TCP client for outgoing connections
- [x] TLS with inverted client/server roles
- [x] Pairing request/accept flow
- [x] Ping send/receive
- [x] Battery status receive
- [x] System tray with theme integration

Next steps:
- [ ] Plugin architecture
- [ ] Notification mirroring
- [ ] Clipboard sync
- [ ] File transfer

## License

MIT

## Credits

Created collaboratively with Claude (Anthropic's AI assistant) using Claude Code.

Protocol documentation and references:
- [Valent Protocol Reference](https://valent.andyholmes.ca/documentation/protocol.html)
- [KDE Connect Wiki](https://community.kde.org/KDEConnect)
- [KDE Connect Source Code](https://github.com/KDE/kdeconnect-kde)
