//! D-Bus Client for cosmic-konnect
//!
//! Provides a high-level client interface for the GUI to communicate with the tray service.
//!
//! ## Usage
//!
//! ```ignore
//! let client = KonnectClient::connect().await?;
//! let devices = client.get_devices().await?;
//! for device in devices {
//!     println!("{}: {}%", device.name, device.battery);
//! }
//! ```

use zbus::{proxy, Connection};

use crate::service::{DeviceInfo, SERVICE_NAME};

/// D-Bus proxy for the konnect service
#[proxy(
    interface = "io.github.cosmickonnect.Service1",
    default_service = "io.github.cosmickonnect.Service1",
    default_path = "/io/github/cosmickonnect/Service1"
)]
trait KonnectService {
    /// Get list of connected devices
    async fn get_devices(&self) -> zbus::Result<Vec<DeviceInfo>>;

    /// Get a specific device by ID (returns empty device if not found)
    async fn get_device(&self, device_id: &str) -> zbus::Result<DeviceInfo>;

    /// Get the number of connected devices
    async fn get_device_count(&self) -> zbus::Result<u32>;

    /// Send ping to a device
    async fn ping_device(&self, device_id: &str) -> zbus::Result<()>;

    /// Ring a device to find it
    async fn find_phone(&self, device_id: &str) -> zbus::Result<()>;

    /// Check if auto-accept pairing is enabled
    async fn get_auto_accept_pairing(&self) -> zbus::Result<bool>;

    /// Enable or disable auto-accept pairing
    async fn set_auto_accept_pairing(&self, enabled: bool) -> zbus::Result<()>;

    /// Get the current status message
    async fn get_status(&self) -> zbus::Result<String>;

    // === Signals ===

    /// Signal emitted when device list changes
    #[zbus(signal)]
    async fn devices_changed(&self) -> zbus::Result<()>;

    /// Signal emitted when a device connects
    #[zbus(signal)]
    async fn device_connected(&self, device_id: String, name: String) -> zbus::Result<()>;

    /// Signal emitted when a device disconnects
    #[zbus(signal)]
    async fn device_disconnected(&self, device_id: String) -> zbus::Result<()>;

    /// Signal emitted when battery status updates
    #[zbus(signal)]
    async fn battery_updated(&self, device_id: String, battery: i32) -> zbus::Result<()>;
}

/// High-level client for the konnect service (running in tray)
pub struct KonnectClient {
    proxy: KonnectServiceProxy<'static>,
}

impl KonnectClient {
    /// Connect to the konnect service
    ///
    /// Returns an error if the tray is not running
    pub async fn connect() -> zbus::Result<Self> {
        let connection = Connection::session().await?;
        let proxy = KonnectServiceProxy::new(&connection).await?;
        Ok(Self { proxy })
    }

    /// Get list of connected devices
    pub async fn get_devices(&self) -> zbus::Result<Vec<DeviceInfo>> {
        self.proxy.get_devices().await
    }

    /// Get a specific device by ID (returns None if device ID is empty, meaning not found)
    pub async fn get_device(&self, device_id: &str) -> zbus::Result<Option<DeviceInfo>> {
        let device = self.proxy.get_device(device_id).await?;
        // The service returns an empty device if not found
        if device.id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(device))
        }
    }

    /// Get the number of connected devices
    pub async fn get_device_count(&self) -> zbus::Result<u32> {
        self.proxy.get_device_count().await
    }

    /// Send ping to a device
    pub async fn ping_device(&self, device_id: &str) -> zbus::Result<()> {
        self.proxy.ping_device(device_id).await
    }

    /// Ring a device to find it
    pub async fn find_phone(&self, device_id: &str) -> zbus::Result<()> {
        self.proxy.find_phone(device_id).await
    }

    /// Check if auto-accept pairing is enabled
    pub async fn get_auto_accept_pairing(&self) -> zbus::Result<bool> {
        self.proxy.get_auto_accept_pairing().await
    }

    /// Enable or disable auto-accept pairing
    pub async fn set_auto_accept_pairing(&self, enabled: bool) -> zbus::Result<()> {
        self.proxy.set_auto_accept_pairing(enabled).await
    }

    /// Get the current status message
    pub async fn get_status(&self) -> zbus::Result<String> {
        self.proxy.get_status().await
    }

    /// Subscribe to devices changed signals
    pub async fn subscribe_devices_changed(
        &self,
    ) -> zbus::Result<DevicesChangedStream> {
        self.proxy.receive_devices_changed().await
    }

    /// Subscribe to device connected signals
    pub async fn subscribe_device_connected(
        &self,
    ) -> zbus::Result<DeviceConnectedStream> {
        self.proxy.receive_device_connected().await
    }

    /// Subscribe to device disconnected signals
    pub async fn subscribe_device_disconnected(
        &self,
    ) -> zbus::Result<DeviceDisconnectedStream> {
        self.proxy.receive_device_disconnected().await
    }

    /// Subscribe to battery updated signals
    pub async fn subscribe_battery_updated(&self) -> zbus::Result<BatteryUpdatedStream> {
        self.proxy.receive_battery_updated().await
    }
}

/// Check if the service is available (tray is running and registered on D-Bus)
pub async fn is_service_available() -> bool {
    if let Ok(connection) = Connection::session().await {
        connection
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "NameHasOwner",
                &SERVICE_NAME,
            )
            .await
            .and_then(|reply| reply.body().deserialize::<bool>())
            .unwrap_or(false)
    } else {
        false
    }
}
