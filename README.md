# cosmic-konnect

KDE Connect protocol implementation for COSMIC desktop.

## Overview

cosmic-konnect implements the [KDE Connect](https://kdeconnect.kde.org/) protocol, allowing COSMIC desktop users to connect their phones, tablets, and other devices for seamless integration.

### Features (Planned)

- [ ] Device discovery
- [ ] Device pairing (TLS/RSA)
- [ ] Ping plugin
- [ ] Battery status
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

# Scan for devices for 5 seconds
cosmic-konnect --list

# Broadcast identity once
cosmic-konnect --broadcast

# Enable verbose logging
cosmic-konnect -v
```

## Protocol

KDE Connect uses:
- **UDP port 1716** for device discovery (broadcast)
- **TCP port 1716** for connections
- **TLS encryption** with self-signed certificates
- **JSON packets** for all communication

Device identity packets are broadcast periodically, allowing devices on the same network to discover each other.

## Development Status

This project is in early development. Currently implemented:
- [x] Device identity generation and persistence
- [x] UDP broadcast for discovery
- [x] Listening for other devices' broadcasts
- [x] Device tracking and timeout

Next steps:
- [ ] TCP listener for incoming connections
- [ ] TLS certificate generation
- [ ] Device pairing flow
- [ ] Plugin architecture

## License

MIT

## Credits

Created collaboratively with Claude (Anthropic's AI assistant) using Claude Code.

Protocol documentation from:
- [Valent Protocol Reference](https://valent.andyholmes.ca/documentation/protocol.html)
- [KDE Connect Wiki](https://community.kde.org/KDEConnect)
