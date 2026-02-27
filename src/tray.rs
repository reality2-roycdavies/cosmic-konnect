//! System tray integration using StatusNotifierItem (SNI) protocol
//!
//! Provides a system tray icon with menu for managing cosmic-konnect.
//! Icon color adapts to COSMIC theme settings.

use image::RgbaImage;
use ksni::blocking::TrayMethods as BlockingTrayMethods;
use ksni::{self, menu::StandardItem, MenuItem, Status, Tray};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

/// Commands from the tray menu
#[derive(Debug, Clone)]
pub enum TrayCommand {
    /// Open settings (future use)
    OpenSettings,
    /// Refresh device list
    RefreshDevices,
    /// Send ping to a specific device
    PingDevice(String),
    /// Ring a device to find it
    FindPhone(String),
    /// Quit the application
    Quit,
}

/// Connected device info for the tray menu
#[derive(Debug, Clone)]
pub struct TrayDevice {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub battery: Option<i32>,
}

/// Shared state for the tray
#[derive(Debug, Default)]
pub struct TrayState {
    pub devices: Vec<TrayDevice>,
    pub is_connected: bool,
}

// ============================================================================
// COSMIC Theme Integration
// ============================================================================

/// Get the host's COSMIC config directory
fn host_cosmic_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".config/cosmic"))
}

/// Get the path to COSMIC's theme mode config file
fn cosmic_theme_path() -> Option<PathBuf> {
    host_cosmic_config_dir().map(|d| d.join("com.system76.CosmicTheme.Mode/v1/is_dark"))
}

/// Get the path to the active theme directory
fn cosmic_theme_dir() -> Option<PathBuf> {
    let is_dark = is_dark_mode();
    let theme_name = if is_dark { "Dark" } else { "Light" };
    host_cosmic_config_dir().map(|d| d.join(format!("com.system76.CosmicTheme.{}/v1", theme_name)))
}

/// Get modification time of theme color files for change detection
fn get_theme_files_mtime() -> Option<std::time::SystemTime> {
    let theme_dir = cosmic_theme_dir()?;
    let accent_path = theme_dir.join("accent");
    let bg_path = theme_dir.join("background");

    let accent_mtime = fs::metadata(&accent_path).ok()?.modified().ok()?;
    let bg_mtime = fs::metadata(&bg_path).ok()?.modified().ok()?;

    Some(accent_mtime.max(bg_mtime))
}

/// Parse a color from COSMIC theme RON format
fn parse_color_from_ron(content: &str, color_name: &str) -> Option<(u8, u8, u8)> {
    let search_pattern = format!("{}:", color_name);
    let start_idx = content.find(&search_pattern)?;
    let block_start = content[start_idx..].find('(')?;
    let block_end = content[start_idx + block_start..].find(')')?;
    let block = &content[start_idx + block_start..start_idx + block_start + block_end + 1];

    let extract_float = |name: &str| -> Option<f32> {
        let pattern = format!("{}: ", name);
        let idx = block.find(&pattern)?;
        let start = idx + pattern.len();
        let end = block[start..].find(',')?;
        block[start..start + end].trim().parse().ok()
    };

    let red = extract_float("red")?;
    let green = extract_float("green")?;
    let blue = extract_float("blue")?;

    Some((
        (red.clamp(0.0, 1.0) * 255.0) as u8,
        (green.clamp(0.0, 1.0) * 255.0) as u8,
        (blue.clamp(0.0, 1.0) * 255.0) as u8,
    ))
}

/// Get theme color for the tray icon (foreground color from background.on)
fn get_theme_color() -> (u8, u8, u8) {
    let default_color = (200, 200, 200);

    let theme_dir = match cosmic_theme_dir() {
        Some(dir) => dir,
        None => return default_color,
    };

    let bg_path = theme_dir.join("background");
    if let Ok(content) = fs::read_to_string(&bg_path) {
        parse_color_from_ron(&content, "on").unwrap_or(default_color)
    } else {
        default_color
    }
}

/// Detect if the system is in dark mode
fn is_dark_mode() -> bool {
    if let Some(path) = cosmic_theme_path() {
        if let Ok(content) = fs::read_to_string(&path) {
            return content.trim() == "true";
        }
    }

    // Fall back to freedesktop portal
    if let Ok(output) = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.portal.Desktop",
            "--object-path",
            "/org/freedesktop/portal/desktop",
            "--method",
            "org.freedesktop.portal.Settings.Read",
            "org.freedesktop.appearance",
            "color-scheme",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("uint32 1") {
            return true;
        }
    }

    true // Default to dark mode
}

// ============================================================================
// Icon Generation
// ============================================================================

/// Phone icon as SVG path data (simplified phone shape)
const PHONE_ICON: &[u8] = include_bytes!("../resources/phone.png");

/// Generate a phone icon with the given color
fn generate_phone_icon(color: (u8, u8, u8), connected: bool) -> Option<RgbaImage> {
    let (r, g, b) = color;

    // Try to load embedded icon
    if let Ok(img) = image::load_from_memory(PHONE_ICON) {
        let mut rgba = img.to_rgba8();
        // Recolor with theme color
        for pixel in rgba.pixels_mut() {
            if pixel[3] > 0 {
                pixel[0] = r;
                pixel[1] = g;
                pixel[2] = b;
            }
        }
        return Some(rgba);
    }

    // Fallback: generate a simple phone icon programmatically
    let size = 32u32;
    let mut img = RgbaImage::new(size, size);

    // Draw a simple phone shape
    let phone_width = 16;
    let phone_height = 28;
    let x_offset = (size - phone_width) / 2;
    let y_offset = (size - phone_height) / 2;

    // Phone body (rounded rectangle approximation)
    for y in y_offset..y_offset + phone_height {
        for x in x_offset..x_offset + phone_width {
            // Skip corners for rounded effect
            let in_corner = (x == x_offset || x == x_offset + phone_width - 1)
                && (y == y_offset || y == y_offset + phone_height - 1);
            if !in_corner {
                img.put_pixel(x, y, image::Rgba([r, g, b, 255]));
            }
        }
    }

    // Screen (hollow center)
    let screen_margin = 2;
    let screen_top = y_offset + 3;
    let screen_bottom = y_offset + phone_height - 5;
    for y in screen_top..screen_bottom {
        for x in (x_offset + screen_margin)..(x_offset + phone_width - screen_margin) {
            img.put_pixel(x, y, image::Rgba([0, 0, 0, 0]));
        }
    }

    // Connection indicator (small dot at bottom)
    if connected {
        let dot_y = y_offset + phone_height - 3;
        let dot_x = x_offset + phone_width / 2;
        // Green dot for connected
        img.put_pixel(dot_x - 1, dot_y, image::Rgba([100, 200, 100, 255]));
        img.put_pixel(dot_x, dot_y, image::Rgba([100, 200, 100, 255]));
        img.put_pixel(dot_x + 1, dot_y, image::Rgba([100, 200, 100, 255]));
    }

    Some(img)
}

// ============================================================================
// Tray Implementation
// ============================================================================

/// The system tray implementation
struct CosmicKonnectTray {
    /// Device list stored directly for ksni updates
    devices: Vec<TrayDevice>,
    command_tx: std::sync::mpsc::Sender<TrayCommand>,
    should_quit: Arc<AtomicBool>,
    /// Revision counter to force icon updates
    revision: u32,
}

impl Tray for CosmicKonnectTray {
    fn id(&self) -> String {
        "io.github.reality2_roycdavies.cosmic-konnect".to_string()
    }

    fn title(&self) -> String {
        // Include device count to trigger NewTitle signal on changes
        if self.devices.is_empty() {
            "Cosmic Konnect".to_string()
        } else {
            format!("Cosmic Konnect ({})", self.devices.len())
        }
    }

    fn icon_name(&self) -> String {
        String::new() // We use pixmap instead
    }

    fn status(&self) -> Status {
        // Change status based on device state - triggers NewStatus signal
        if self.devices.is_empty() {
            Status::Passive
        } else {
            Status::Active
        }
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let connected = !self.devices.is_empty();

        let theme_color = get_theme_color();
        let img = match generate_phone_icon(theme_color, connected) {
            Some(mut img) => {
                // Slightly modify a single pixel based on revision to force icon refresh
                // This triggers the desktop to re-fetch everything including menu
                let rev_byte = ((self.revision % 10) as u8).saturating_add(245); // 245-254, nearly invisible
                if let Some(pixel) = img.get_pixel_mut_checked(0, 0) {
                    pixel[3] = pixel[3].saturating_sub(1).max(rev_byte.min(pixel[3]));
                }
                img
            }
            None => return vec![],
        };

        // Convert RGBA to ARGB (network byte order for D-Bus)
        let mut argb_data = Vec::with_capacity((img.width() * img.height() * 4) as usize);
        for pixel in img.pixels() {
            let [r, g, b, a] = pixel.0;
            argb_data.push(a);
            argb_data.push(r);
            argb_data.push(g);
            argb_data.push(b);
        }

        vec![ksni::Icon {
            width: img.width() as i32,
            height: img.height() as i32,
            data: argb_data,
        }]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let device_count = self.devices.len();

        ksni::ToolTip {
            title: "Cosmic Konnect".to_string(),
            description: if device_count == 0 {
                "No devices connected".to_string()
            } else if device_count == 1 {
                format!("1 device: {}", self.devices[0].name)
            } else {
                format!("{} devices connected", device_count)
            },
            icon_name: String::new(),
            icon_pixmap: vec![],
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = vec![];

        // Open Window
        let tx = self.command_tx.clone();
        items.push(MenuItem::Standard(StandardItem {
            label: "Open Window".to_string(),
            icon_name: "preferences-system".to_string(),
            activate: Box::new(move |_tray: &mut Self| {
                let _ = tx.send(TrayCommand::OpenSettings);
            }),
            ..Default::default()
        }));

        items.push(MenuItem::Separator);

        // Quit
        items.push(MenuItem::Standard(StandardItem {
            label: "Quit".to_string(),
            icon_name: "application-exit".to_string(),
            activate: Box::new(|tray: &mut Self| {
                tray.should_quit.store(true, Ordering::SeqCst);
                let _ = tray.command_tx.send(TrayCommand::Quit);
            }),
            ..Default::default()
        }));

        items
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        // Open window on left click
        let _ = self.command_tx.send(TrayCommand::OpenSettings);
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Internal update commands for the tray thread
enum TrayUpdate {
    AddDevice(TrayDevice),
    RemoveDevice(String),
    UpdateBattery(String, i32),
}

/// Handle for controlling the tray from the application
pub struct TrayHandle {
    state: Arc<Mutex<TrayState>>,
    update_tx: std::sync::mpsc::Sender<TrayUpdate>,
}

impl TrayHandle {
    /// Update the list of connected devices
    #[allow(dead_code)]
    pub fn update_devices(&self, devices: Vec<TrayDevice>) {
        let mut state = self.state.lock().unwrap();
        state.devices = devices;
        state.is_connected = !state.devices.is_empty();
        // Don't call ksni directly - the tray thread will pick up state changes
    }

    /// Update a single device's battery level
    pub fn update_device_battery(&self, device_id: &str, battery: i32) {
        // Send update through channel to tray thread
        let _ = self.update_tx.send(TrayUpdate::UpdateBattery(device_id.to_string(), battery));
    }

    /// Add a device to the list
    pub fn add_device(&self, device: TrayDevice) {
        // Send update through channel to tray thread
        let _ = self.update_tx.send(TrayUpdate::AddDevice(device));
    }

    /// Remove a device from the list
    pub fn remove_device(&self, device_id: &str) {
        // Send update through channel to tray thread
        let _ = self.update_tx.send(TrayUpdate::RemoveDevice(device_id.to_string()));
    }
}

/// Start the system tray service in a separate thread (required because ksni uses blocking D-Bus)
/// Returns a handle for controlling the tray and a receiver for commands
pub fn start_tray() -> Result<(TrayHandle, std::sync::mpsc::Receiver<TrayCommand>), String> {
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (update_tx, update_rx) = std::sync::mpsc::channel::<TrayUpdate>();
    let state = Arc::new(Mutex::new(TrayState::default()));
    let should_quit = Arc::new(AtomicBool::new(false));

    let should_quit_clone = should_quit.clone();
    let command_tx_clone = command_tx.clone();

    // Channel to signal tray is ready
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        // Retry with exponential backoff to wait for StatusNotifierWatcher
        let max_retries = 10;
        let mut delay_ms = 500;
        let mut last_error = String::new();
        let mut ksni_handle_opt: Option<ksni::blocking::Handle<CosmicKonnectTray>> = None;

        for attempt in 1..=max_retries {
            std::thread::sleep(Duration::from_millis(delay_ms));

            let tray = CosmicKonnectTray {
                devices: Vec::new(),
                command_tx: command_tx_clone.clone(),
                should_quit: should_quit_clone.clone(),
                revision: 0,
            };

            // Spawn the tray service
            match BlockingTrayMethods::disable_dbus_name(tray, false).spawn() {
                Ok(handle) => {
                    ksni_handle_opt = Some(handle);
                    break;
                }
                Err(e) => {
                    last_error = format!("{}", e);
                    eprintln!("Tray spawn attempt {}/{} failed: {} (retrying in {}ms)",
                              attempt, max_retries, last_error, delay_ms * 2);
                    delay_ms = (delay_ms * 2).min(10000); // Cap at 10 seconds
                }
            }
        }

        let ksni_handle = match ksni_handle_opt {
            Some(h) => h,
            None => {
                let _ = ready_tx.send(Err(format!("Failed to spawn tray after {} attempts: {}", max_retries, last_error)));
                return;
            }
        };

        // Signal ready
        let _ = ready_tx.send(Ok(()));

        // Set up theme watcher
        let (config_tx, config_rx) = channel();
        let notify_config = NotifyConfig::default().with_poll_interval(Duration::from_secs(1));

        let _watcher: Option<RecommendedWatcher> = {
            let tx = config_tx.clone();
            let mut watcher: Result<RecommendedWatcher, _> = Watcher::new(
                move |res: Result<notify::Event, _>| {
                    if let Ok(event) = res {
                        if matches!(
                            event.kind,
                            notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                        ) {
                            let _ = tx.send(());
                        }
                    }
                },
                notify_config,
            );
            if let Ok(ref mut w) = watcher {
                if let Some(theme_path) = cosmic_theme_path() {
                    if let Some(watch_dir) = theme_path.parent() {
                        let _ = w.watch(watch_dir, RecursiveMode::NonRecursive);
                    }
                }
                if let Some(theme_dir) = cosmic_theme_dir() {
                    let _ = w.watch(&theme_dir, RecursiveMode::NonRecursive);
                }
            }
            watcher.ok()
        };

        let mut tracked_mtime = get_theme_files_mtime();
        let mut last_check = Instant::now();

        // Main tray thread loop - handles theme changes and state updates
        loop {
            if should_quit_clone.load(Ordering::SeqCst) {
                break;
            }

            // Collect pending updates
            let mut pending_updates: Vec<TrayUpdate> = Vec::new();
            while let Ok(update) = update_rx.try_recv() {
                pending_updates.push(update);
            }

            // Check for theme changes
            let theme_changed = config_rx.try_recv().is_ok();

            let mut theme_file_changed = false;
            if last_check.elapsed() >= Duration::from_millis(500) {
                last_check = Instant::now();
                let new_mtime = get_theme_files_mtime();
                if new_mtime != tracked_mtime {
                    tracked_mtime = new_mtime;
                    theme_file_changed = true;
                }
            }

            // Apply updates inside the ksni update closure
            if !pending_updates.is_empty() || theme_changed || theme_file_changed {
                let update_count = pending_updates.len();
                ksni_handle.update(|tray| {
                    // Increment revision to force icon refresh (triggers menu re-fetch)
                    tray.revision = tray.revision.wrapping_add(1);

                    for update in &pending_updates {
                        match update {
                            TrayUpdate::AddDevice(device) => {
                                println!("[TRAY] Adding device: {} ({})", device.name, device.id);
                                tray.devices.retain(|d| d.id != device.id);
                                tray.devices.push(device.clone());
                                println!("[TRAY] Total devices now: {}", tray.devices.len());
                            }
                            TrayUpdate::RemoveDevice(device_id) => {
                                println!("[TRAY] Removing device: {}", device_id);
                                tray.devices.retain(|d| d.id != *device_id);
                            }
                            TrayUpdate::UpdateBattery(device_id, battery) => {
                                println!("[TRAY] Updating battery for {}: {}%", device_id, battery);
                                if let Some(device) = tray.devices.iter_mut().find(|d| d.id == *device_id) {
                                    device.battery = Some(*battery);
                                }
                            }
                        }
                    }
                });
                if update_count > 0 {
                    println!("[TRAY] Processed {} updates", update_count);
                }
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // Wait for tray to be ready (longer timeout for retry attempts)
    ready_rx
        .recv_timeout(Duration::from_secs(120))
        .map_err(|_| "Timeout waiting for tray to start".to_string())??;

    info!("System tray started");

    Ok((
        TrayHandle {
            state,
            update_tx,
        },
        command_rx,
    ))
}
