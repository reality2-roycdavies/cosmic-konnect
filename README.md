# Cosmic Konnect

A device connectivity application for the [COSMIC desktop environment](https://system76.com/cosmic), enabling seamless communication between your Linux desktop and Android devices.

**Android companion app:** [cosmic-konnect-android](https://github.com/reality2-roycdavies/cosmic-konnect-android)

## Features

- **Device Discovery** - Automatically discover devices on your local network
- **Clipboard Sync** - Share clipboard content between desktop and phone
- **Ping/Find Device** - Send pings between devices, ring your phone to find it
- **Desktop Notifications** - Get notified when clipboard is received
- **System Tray** - Runs quietly in your system tray with quick access to features
- **Autostart** - Automatically starts on login

### Coming Soon

- BLE (Bluetooth Low Energy) discovery
- Wi-Fi Direct support
- File transfer
- Notification mirroring

## Installation

### Dependencies

**Arch Linux / Manjaro:**
```bash
sudo pacman -S rust gtk4 libadwaita openssl
```

**Fedora:**
```bash
sudo dnf install rust cargo gtk4-devel libadwaita-devel openssl-devel
```

**Ubuntu / Debian:**
```bash
sudo apt install rustc cargo libgtk-4-dev libadwaita-1-dev libssl-dev
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/reality2-roycdavies/cosmic-konnect.git
cd cosmic-konnect

# Build release version
cargo build --release

# The binary will be at target/release/cosmic-konnect
```

### Installing

```bash
# Install to ~/.local/bin (make sure it's in your PATH)
mkdir -p ~/.local/bin
cp target/release/cosmic-konnect ~/.local/bin/

# Or install system-wide
sudo cp target/release/cosmic-konnect /usr/local/bin/
```

## Usage

### System Tray Mode (Recommended)

Run with system tray icon - this is the recommended way to use the app:

```bash
cosmic-konnect --tray
```

The app will:
- Start in the system tray
- Automatically discover devices on your network
- Auto-connect to previously paired devices
- Set up autostart for future logins

### Other Modes

```bash
# Open GUI (starts tray first if not running)
cosmic-konnect

# Discover devices (CLI mode)
cosmic-konnect --discover

# List discovered devices and exit
cosmic-konnect --list

# Enable verbose logging
cosmic-konnect --tray --verbose
```

### Pairing with Android Device

1. Start the desktop app: `cosmic-konnect --tray`
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
3. Try restarting the service (click refresh button or restart app)

### Connection drops frequently

1. Check network stability
2. Ensure the phone isn't in battery saver mode (may kill background services)
3. Check Android battery optimization settings for Cosmic Konnect

### Verbose logging

```bash
RUST_LOG=debug cosmic-konnect --tray --verbose
```

## Protocol

Cosmic Konnect uses its own lightweight protocol (CKP - Cosmic Konnect Protocol) with:
- MessagePack encoding for efficiency
- X25519 key exchange for secure pairing
- ChaCha20-Poly1305 encryption for messages

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Related Projects

- [cosmic-konnect-android](https://github.com/reality2-roycdavies/cosmic-konnect-android) - Android companion app
- [COSMIC Desktop](https://github.com/pop-os/cosmic-epoch) - The COSMIC desktop environment
- [KDE Connect](https://kdeconnect.kde.org/) - Inspiration for this project
