name := 'cosmic-konnect'
daemon := 'cosmic-konnect-daemon'
appid := 'io.github.reality2_roycdavies.cosmic-konnect'

# Default recipe: build release
default: build-release

# Build in debug mode
build-debug:
    cargo build
    cd cosmic-konnect-daemon && cargo build

# Build in release mode
build-release:
    cargo build --release
    cd cosmic-konnect-daemon && cargo build --release

# Run in debug mode
run:
    cargo run

# Run in release mode
run-release:
    cargo run --release

# Check code with clippy
check:
    cargo clippy --all-features

# Format code
fmt:
    cargo fmt

# Clean build artifacts
clean:
    cargo clean
    cd cosmic-konnect-daemon && cargo clean

# Install to local user
install-local:
    #!/bin/bash
    set -e

    echo "Stopping any running instances..."
    pkill -x "{{name}}" 2>/dev/null || true
    pkill -x "{{daemon}}" 2>/dev/null || true
    sleep 1

    # Install binaries
    mkdir -p ~/.local/bin
    rm -f ~/.local/bin/{{name}}
    rm -f ~/.local/bin/{{daemon}}
    cp target/release/{{name}} ~/.local/bin/
    cp cosmic-konnect-daemon/target/release/{{daemon}} ~/.local/bin/

    # Install desktop entry
    mkdir -p ~/.local/share/applications
    cp resources/{{appid}}.desktop ~/.local/share/applications/

    # Install icons
    mkdir -p ~/.local/share/icons/hicolor/scalable/apps
    cp resources/{{appid}}.svg ~/.local/share/icons/hicolor/scalable/apps/
    mkdir -p ~/.local/share/icons/hicolor/symbolic/apps
    cp resources/{{appid}}-symbolic.svg ~/.local/share/icons/hicolor/symbolic/apps/
    cp resources/{{appid}}-connected-symbolic.svg ~/.local/share/icons/hicolor/symbolic/apps/
    cp resources/{{appid}}-disconnected-symbolic.svg ~/.local/share/icons/hicolor/symbolic/apps/

    # Install systemd service
    mkdir -p ~/.config/systemd/user
    cp resources/cosmic-konnect.service ~/.config/systemd/user/
    systemctl --user daemon-reload

    # Install applet registration for cosmic-applet-settings
    mkdir -p ~/.local/share/cosmic-applet-settings/applets
    cp resources/applet-settings.json ~/.local/share/cosmic-applet-settings/applets/{{name}}.json

    echo ""
    echo "Installation complete!"
    echo "Add the applet to your COSMIC panel to use it."
    echo ""
    echo "To start the daemon:"
    echo "  systemctl --user start cosmic-konnect"
    echo "  systemctl --user enable cosmic-konnect"

# Uninstall from local user
uninstall-local:
    #!/bin/bash
    set -e

    echo "Stopping services..."
    systemctl --user stop cosmic-konnect 2>/dev/null || true
    systemctl --user disable cosmic-konnect 2>/dev/null || true
    pkill -x "{{name}}" 2>/dev/null || true

    rm -f ~/.local/bin/{{name}}
    rm -f ~/.local/bin/{{daemon}}
    rm -f ~/.local/share/applications/{{appid}}.desktop
    rm -f ~/.local/share/icons/hicolor/scalable/apps/{{appid}}.svg
    rm -f ~/.local/share/icons/hicolor/symbolic/apps/{{appid}}-symbolic.svg
    rm -f ~/.local/share/icons/hicolor/symbolic/apps/{{appid}}-connected-symbolic.svg
    rm -f ~/.local/share/icons/hicolor/symbolic/apps/{{appid}}-disconnected-symbolic.svg
    rm -f ~/.config/systemd/user/cosmic-konnect.service
    rm -f ~/.local/share/cosmic-applet-settings/applets/{{name}}.json
    systemctl --user daemon-reload

    echo "Uninstall complete."

# Build and run
br: build-debug run
