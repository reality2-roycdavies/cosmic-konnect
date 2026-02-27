# Cosmic Konnect

A device connectivity applet for the [COSMIC desktop environment](https://system76.com/cosmic), enabling seamless communication between your Linux desktop and Android devices. Runs as a native COSMIC panel applet with a background daemon.

> **Early Alpha** - This project is in early alpha. Core functionality (discovery, pairing, clipboard sync) is being developed but many features are not yet working. Expect breaking changes and incomplete behaviour.

**Android companion app:** [cosmic-konnect-android](https://github.com/reality2-roycdavies/cosmic-konnect-android)

## Features

- **Panel Applet** - Native COSMIC panel applet showing device connectivity status
- **Device Discovery** - Automatically discover devices on your local network
- **Clipboard Sync** - Share clipboard content between desktop and phone
- **Ping/Find Device** - Send pings between devices, ring your phone to find it
- **Desktop Notifications** - Get notified when clipboard is received
- **Background Daemon** - Runs as a systemd user service for reliable connectivity

### Coming Soon

- BLE (Bluetooth Low Energy) discovery
- Wi-Fi Direct support
- File transfer
- Notification mirroring

## Installation

### Dependencies

**Arch Linux / Manjaro:**
```bash
sudo pacman -S rust just gtk4 libadwaita openssl
```

**Fedora:**
```bash
sudo dnf install rust cargo just gtk4-devel libadwaita-devel openssl-devel
```

**Ubuntu / Debian:**
```bash
sudo apt install rustc cargo just libgtk-4-dev libadwaita-1-dev libssl-dev
```

### Building & Installing

```bash
git clone https://github.com/reality2-roycdavies/cosmic-konnect.git
cd cosmic-konnect

# Build both applet and daemon
just build-release

# Install to ~/.local/ (binaries, icons, desktop entry, systemd service)
just install-local
```

### Starting the Daemon

```bash
# Start the background daemon
systemctl --user start cosmic-konnect

# Enable auto-start on login
systemctl --user enable cosmic-konnect
```

### Adding to Panel

1. Open COSMIC Settings > Desktop > Panel
2. Add the "Cosmic Konnect" applet to your panel
3. Click the panel icon to see connected devices and actions

## Usage

### Panel Applet (Default)

Run with no arguments to start as a COSMIC panel applet:

```bash
cosmic-konnect
```

The applet shows a connectivity icon in the panel. Click it to see:
- Connection status
- Discovered and connected devices
- Per-device actions (Pair, Ring, Ping)
- Quick access to Settings

### Other Modes

```bash
# Open settings window directly
cosmic-konnect --settings

# List discovered devices via daemon (CLI)
cosmic-konnect --list

# Run local network discovery (CLI, 5 second scan)
cosmic-konnect --discover

# Show help
cosmic-konnect --help
```

### Settings

Settings are accessible via:
- The "Settings..." button in the applet popup
- `cosmic-applet-settings konnect` (if the unified settings app is installed)
- `cosmic-konnect --settings` (standalone window)

### Pairing with Android Device

1. Ensure the daemon is running: `systemctl --user start cosmic-konnect`
2. Install and open the [Android companion app](https://github.com/reality2-roycdavies/cosmic-konnect-android)
3. Both devices should discover each other automatically on the same network
4. Tap the device in the Android app to connect
5. Accept the pairing request on both devices

### Sharing Clipboard

**Desktop to Phone:**
- Copy text on your desktop
- The clipboard will automatically sync to your phone (when connected)
- Phone will vibrate to confirm receipt

**Phone to Desktop:**
- Copy text on your phone
- Tap the clipboard icon in the Android app
- A notification will appear on your desktop with the clipboard content

## Configuration

Configuration is stored in `~/.config/cosmic-konnect/`:

- `identity.json` - Device identity and keys
- `paired_devices.json` - List of paired devices

## Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| 17160 | UDP | Device discovery broadcasts |
| 17161 | TCP | Encrypted connections |

Make sure these ports are allowed through your firewall for devices to discover each other.

## Troubleshooting

### Devices not discovering each other

1. Ensure both devices are on the same network
2. Check firewall allows UDP 17160 and TCP 17161
3. Check daemon is running: `systemctl --user status cosmic-konnect`
4. Restart daemon: `systemctl --user restart cosmic-konnect`

### Connection drops frequently

1. Check network stability
2. Ensure the phone isn't in battery saver mode (may kill background services)
3. Check Android battery optimization settings for Cosmic Konnect

### Verbose logging

```bash
RUST_LOG=debug cosmic-konnect-daemon
```

## Uninstalling

```bash
just uninstall-local
```

## Protocol

Cosmic Konnect uses its own lightweight protocol (CKP - Cosmic Konnect Protocol) with:
- MessagePack encoding for efficiency
- X25519 key exchange for secure pairing
- ChaCha20-Poly1305 encryption for messages

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the full protocol specification.

## Educational Documentation

This project was developed as an educational resource demonstrating cross-platform application development. The [docs/development-logs](docs/development-logs) directory contains:

- [Thematic Analysis](docs/development-logs/THEMATIC_ANALYSIS.md) - In-depth analysis of the development process covering:
  - Protocol design decisions
  - Cross-platform architecture patterns
  - Android development (services, Compose, receivers)
  - Rust async patterns (Tokio, channels)
  - Encryption and security implementation
  - Debugging techniques

## COSMIC Applet Suite

Part of a suite of custom COSMIC panel applets with a [unified settings app](https://github.com/reality2-roycdavies/cosmic-applet-settings):

| Applet | Description |
|--------|-------------|
| **[cosmic-applet-settings](https://github.com/reality2-roycdavies/cosmic-applet-settings)** | Unified settings app for the applet suite |
| **[cosmic-konnect](https://github.com/reality2-roycdavies/cosmic-konnect)** | Device connectivity (KDE Connect for COSMIC) |
| **[cosmic-runkat](https://github.com/reality2-roycdavies/cosmic-runkat)** | Animated running cat CPU indicator for the panel |
| **[cosmic-bing-wallpaper](https://github.com/reality2-roycdavies/cosmic-bing-wallpaper)** | Daily Bing wallpaper manager with auto-update |
| **[cosmic-pie-menu](https://github.com/reality2-roycdavies/cosmic-pie-menu)** | Radial/pie menu app launcher with gesture support |
| **[cosmic-tailscale](https://github.com/reality2-roycdavies/cosmic-tailscale)** | Tailscale VPN status and control applet |
| **[cosmic-hotspot](https://github.com/reality2-roycdavies/cosmic-hotspot)** | WiFi hotspot toggle applet |

## Related Projects

| Project | Description |
|---------|-------------|
| **[cosmic-konnect-android](https://github.com/reality2-roycdavies/cosmic-konnect-android)** | Android companion app for Cosmic Konnect |
| **[COSMIC Desktop](https://github.com/pop-os/cosmic-epoch)** | The COSMIC desktop environment |
| **[KDE Connect](https://kdeconnect.kde.org/)** | Inspiration for this project |

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
