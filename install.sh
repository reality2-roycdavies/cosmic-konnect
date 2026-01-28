#!/bin/bash
# Cosmic Konnect installer
# Installs daemon and tray app for the current user

set -e

echo "=== Cosmic Konnect Installer ==="
echo

# Build both
echo "[1/5] Building daemon..."
cd cosmic-konnect-daemon
cargo build --release
cd ..

echo "[2/5] Building tray app..."
cargo build --release

# Install binaries
echo "[3/5] Installing binaries to ~/.local/bin..."
mkdir -p ~/.local/bin
cp target/release/cosmic-konnect ~/.local/bin/
cp cosmic-konnect-daemon/target/release/cosmic-konnect-daemon ~/.local/bin/

# Install systemd service
echo "[4/5] Installing systemd user service..."
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/cosmic-konnect.service << 'EOF'
[Unit]
Description=Cosmic Konnect Daemon
Documentation=https://github.com/reality2-roycdavies/cosmic-konnect
After=graphical-session.target bluetooth.target network.target
Wants=bluetooth.target

[Service]
Type=simple
ExecStart=%h/.local/bin/cosmic-konnect-daemon
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload

# Install autostart for tray
echo "[5/5] Installing autostart entry..."
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/cosmic-konnect.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Cosmic Konnect
Comment=Device connectivity for COSMIC Desktop
Exec=cosmic-konnect --tray
Icon=phone
Terminal=false
Categories=Utility;Network;
X-GNOME-Autostart-enabled=true
StartupNotify=false
EOF

echo
echo "=== Installation Complete ==="
echo
echo "To start now:"
echo "  systemctl --user start cosmic-konnect  # Start daemon"
echo "  cosmic-konnect --tray                   # Start tray (auto-starts daemon)"
echo
echo "To enable on login:"
echo "  systemctl --user enable cosmic-konnect"
echo
echo "The tray app will auto-start the daemon if needed."
echo "Both will start automatically on next login."
