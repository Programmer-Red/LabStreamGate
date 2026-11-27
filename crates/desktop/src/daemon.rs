use std::{
    collections::VecDeque,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_channel::{Receiver, Sender, unbounded};
use labstreamgate::tunnel::Tunnel;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{
    launcher,
    models::{DesktopConfig, FeatureFlags, InstanceData, LogEntry, ScopeData},
};

pub mod api;
mod workers;

/// Canonical scope host representing all official `https://*.xujclab.com` origins.
pub const OFFICIAL_XUJCLAB_SCOPE_HOST: &str = "https://ctf.xujclab.com";
pub const OFFICIAL_XUJCLAB_SCOPE_NAME: &str = "xujclab";

/// Returns `true` when `origin` is an HTTPS origin under `xujclab.com` or `*.xujclab.com`
/// (with or without an explicit port, such as `https://campus.xujclab.com:8798` or
/// `https://edge-hk.xujclab.com:50412`).
pub fn is_official_xujclab_origin(origin: &str) -> bool {
    let trimmed = origin.trim().trim_end_matches('/');
    let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("HTTPS://"))
    else {
        return false;
    };
    if rest.is_empty()
        || rest
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b' '))
    {
        return false;
    }
    let host = if let Some((h, port)) = rest.rsplit_once(':') {
        if port.parse::<u16>().is_err() {
            return false;
        }
        h
    } else {
        rest
    };
    let lower = host.to_ascii_lowercase();
    if lower == "xujclab.com" {
        return true;
    }
    if let Some(sub) = lower.strip_suffix(".xujclab.com") {
        return !sub.is_empty()
            && !sub.starts_with('.')
            && !sub.contains("..")
            && sub
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
    }
    false
}

/// Maps an HTTP `Origin` header value onto its canonical scope host.
/// All official `https://*.xujclab.com(:port)` origins share a single `xujclab` scope.
pub fn canonical_scope_host(origin: &str) -> String {
    let normalized = origin.trim().trim_end_matches('/');
    if is_official_xujclab_origin(normalized) {
        OFFICIAL_XUJCLAB_SCOPE_HOST.to_string()
    } else {
        normalized.to_string()
    }
}

/// Migrates legacy `xujclab.com` scopes onto the canonical `https://ctf.xujclab.com`
/// scope and ensures the official `xujclab` scope is ready out of the box.
pub fn normalize_scopes(raw_scopes: Vec<ScopeData>) -> Vec<ScopeData> {
    let mut normalized: Vec<ScopeData> = Vec::new();
    for mut scope in raw_scopes {
        let canonical = canonical_scope_host(&scope.host);
        if canonical.is_empty() {
            continue;
        }
        scope.host = canonical.clone();
        if canonical == OFFICIAL_XUJCLAB_SCOPE_HOST
            && (scope.name.is_empty() || scope.name.contains("xujclab"))
        {
            scope.name = OFFICIAL_XUJCLAB_SCOPE_NAME.to_string();
        }
        if let Some(existing) = normalized.iter_mut().find(|s| s.host == canonical) {
            if scope.state == "allowed" {
                existing.state = "allowed".to_string();
            }
            existing.features |= scope.features;
        } else {
            normalized.push(scope);
        }
    }

    if !normalized
        .iter()
        .any(|s| s.host == OFFICIAL_XUJCLAB_SCOPE_HOST)
    {
        normalized.insert(
            0,
            ScopeData {
                host: OFFICIAL_XUJCLAB_SCOPE_HOST.to_string(),
                name: OFFICIAL_XUJCLAB_SCOPE_NAME.to_string(),
                state: "allowed".to_string(),
                features: FeatureFlags::Basic,
                settings: Default::default(),
            },
        );
    }

    normalized
}

/// Events pushed from background (tokio) tasks into the UI thread.
#[derive(Clone, Debug)]
pub enum UiEvent {
    /// The API server bound successfully.
    Online { port: u16 },
    /// Instances / scopes changed; the UI should re-read shared state.
    Refresh,
    /// A new log line was streamed from the log file.
    Log(LogEntry),
    /// A batch of log lines (used by the event pump to coalesce floods).
    Logs(Vec<LogEntry>),
    /// Whether a newer release exists on GitHub.
    HasUpdates(bool),
    /// Another instance or pending scope authorization asked this app to pop up its window.
    Popup,
    /// The system tray asked the app to quit.
    Quit,
    /// Cursor blink tick for the get-started page.
    CursorTick,
}

/// Shared state between the background daemon and the UI.
#[derive(Clone)]
pub struct ServerState {
    pub instances: Arc<RwLock<Vec<ProxyInstance>>>,
    pub scopes: Arc<RwLock<Vec<ScopeData>>>,
    pub settings: Arc<RwLock<DesktopConfig>>,
    /// Whether the OS system tray icon is currently active (safe to hide window on close).
    pub tray_active: Arc<AtomicBool>,
    /// The API server port, once bound.
    pub api_port: Arc<RwLock<u16>>,
    /// Whether a newer release exists on GitHub.
    pub has_updates: Arc<RwLock<bool>>,
    /// Accumulated log entries (capped), so a reopened window can restore them.
    pub logs: Arc<RwLock<VecDeque<LogEntry>>>,
    pub events: Sender<UiEvent>,
}

impl ServerState {
    pub fn should_hide_to_tray_on_close(&self) -> bool {
        self.settings.blocking_read().running_in_tray && self.tray_active.load(Ordering::Relaxed)
    }
}

/// A proxied tunnel instance, wrapping the underlying `labstreamgate::tunnel::Tunnel`.
pub struct ProxyInstance {
    pub data: InstanceData,
    _tunnel: Tunnel,
}

impl ProxyInstance {
    pub fn new(
        label: impl AsRef<str>, scope_host: impl AsRef<str>, browser: Option<String>,
        listener: tokio::net::TcpListener, remote: impl AsRef<str>,
    ) -> Self {
        let client_label = format!("Desktop {}", env!("CARGO_PKG_VERSION"));
        let tunnel =
            Tunnel::new_with_metadata(remote.as_ref(), listener, client_label, browser.clone());

        Self {
            data: InstanceData {
                label: label.as_ref().to_string(),
                remote: remote.as_ref().to_string(),
                local: tunnel.local.clone(),
                latency: -1,
                scope_host: scope_host.as_ref().to_string(),
                browser,
            },
            _tunnel: tunnel,
        }
    }
}

impl From<&ProxyInstance> for InstanceData {
    fn from(value: &ProxyInstance) -> Self {
        value.data.clone()
    }
}

impl std::ops::Deref for ProxyInstance {
    type Target = InstanceData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for ProxyInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

static TOKIO: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn tokio() -> &'static tokio::runtime::Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

/// Installs a default crypto provider for rustls, preferring AWS-LC with a
/// ring fallback. Exits the process when no backend is available.
pub fn setup_crypto() {
    use rustls::crypto;

    match crypto::aws_lc_rs::default_provider().install_default() {
        Ok(_) => info!("Using `AWS Libcrypto` as default crypto backend."),
        Err(err) => {
            error!("`AWS Libcrypto` is not available: {:?}", err);
            warn!("Try to use `ring` as default crypto backend.");
            crypto::ring::default_provider()
                .install_default()
                .inspect_err(|err| {
                    error!("`ring` is not available: {:?}", err);
                    error!("All crypto backend are not available, exiting...");
                    std::process::exit(1);
                })
                .ok();
            info!("Using `ring` as default crypto backend.");
        }
    }
}

/// Creates the tokio runtime and shared state, then starts the background
/// workers (API server, latency monitor, log streaming, update check).
pub fn spawn_background() -> (ServerState, Receiver<UiEvent>) {
    if let Some(long_os) = sysinfo::System::long_os_version() {
        let arch = sysinfo::System::cpu_arch();
        labstreamgate::device::set_host_os_override(format!("{long_os} ({arch})"));
    }

    let (events, events_rx) = unbounded();
    let state = ServerState {
        instances: Arc::new(RwLock::new(vec![])),
        scopes: Arc::new(RwLock::new(normalize_scopes(vec![]))),
        settings: Arc::new(RwLock::new(DesktopConfig::default())),
        tray_active: Arc::new(AtomicBool::new(false)),
        api_port: Arc::new(RwLock::new(0)),
        has_updates: Arc::new(RwLock::new(false)),
        logs: Arc::new(RwLock::new(VecDeque::new())),
        events,
    };

    // API server.
    let server_state = state.clone();
    tokio().spawn(async move {
        api::serve(server_state).await;
    });

    // Latency worker.
    let worker_state = state.clone();
    tokio().spawn(async move {
        workers::latency_loop(worker_state).await;
    });

    // Log streaming.
    let log_state = state.clone();
    tokio().spawn(async move {
        workers::stream_logs(log_state).await;
    });

    // Update check.
    let update_state = state.clone();
    tokio().spawn(async move {
        workers::check_for_updates(update_state).await;
    });

    // Cursor blink for the get-started page.
    let cursor_state = state.clone();
    tokio().spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if cursor_state.events.send(UiEvent::CursorTick).await.is_err() {
                break;
            }
        }
    });

    (state, events_rx)
}

/// Loads persisted config and scopes into the shared state. Called once at
/// startup before the UI reads them.
pub fn load_persisted_state(state: &ServerState) {
    // Scopes
    let config_file = launcher::project_dirs().config_dir().join("scopes.toml");
    let scopes: ScopesConfig = std::fs::read_to_string(&config_file)
        .ok()
        .and_then(|config| match toml::from_str(&config) {
            Ok(scopes) => Some(scopes),
            Err(e) => {
                error!("Failed to parse scopes config file: {e}");
                None
            }
        })
        .unwrap_or(ScopesConfig { scopes: vec![] });
    let migrated = normalize_scopes(scopes.scopes);
    debug!("Loaded scopes: {:?}", migrated);
    write_scopes_to_disk(&migrated);
    *state.scopes.blocking_write() = migrated;

    // Config
    let config_file = launcher::project_dirs().config_dir().join("config.toml");
    let config: DesktopConfig = std::fs::read_to_string(&config_file)
        .ok()
        .and_then(|config| match toml::from_str(&config) {
            Ok(config) => Some(config),
            Err(e) => {
                error!("Failed to parse config file: {e}");
                None
            }
        })
        .unwrap_or_default();
    debug!("Loaded config: {:?}", config);
    *state.settings.blocking_write() = config;
}

/// Persists config and scopes, then cleans up runtime files. Called when the
/// main window is closed.
pub fn shutdown(state: &ServerState) {
    save_config(&state.settings);
    save_scopes(&state.scopes);
    // Archive the current session's log and drop the single-instance lock.
    // Idempotent, safe to call from both the window-close handler and the
    // app-quit observer.
    launcher::archive_current_log();
    launcher::remove_lock();
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ScopesConfig {
    scopes: Vec<ScopeData>,
}

fn write_scopes_to_disk(scopes: &[ScopeData]) {
    let config_file = launcher::project_dirs().config_dir().join("scopes.toml");
    let config_obj = ScopesConfig {
        scopes: scopes.to_vec(),
    };
    let config = toml::to_string(&config_obj).unwrap_or_else(|e| {
        error!("Failed to serialize scopes: {}", e);
        String::new()
    });
    persist_to(config_file, config);
}

fn save_scopes(scopes: &Arc<RwLock<Vec<ScopeData>>>) {
    write_scopes_to_disk(&scopes.blocking_read());
}

fn write_settings_to_disk(settings: &DesktopConfig) {
    let config_file = launcher::project_dirs().config_dir().join("config.toml");
    let config = toml::to_string(settings).unwrap_or_else(|e| {
        error!("Failed to serialize config: {}", e);
        String::new()
    });
    persist_to(config_file, config);
}

fn save_config(settings: &Arc<RwLock<DesktopConfig>>) {
    write_settings_to_disk(&settings.blocking_read());
}

/// Immediately persists the current scopes to `scopes.toml`. Async variant
/// for use inside the tokio runtime (axum handlers / background workers).
pub(crate) async fn persist_scopes(state: &ServerState) {
    let scopes = state.scopes.read().await;
    write_scopes_to_disk(&scopes);
}

/// Immediately persists the current settings to `config.toml`. Sync variant
/// for use on the UI thread (theme / language handlers).
pub(crate) fn persist_settings_sync(state: &ServerState) {
    write_settings_to_disk(&state.settings.blocking_read());
}

fn persist_to(config_file: std::path::PathBuf, config: String) {
    if let Some(parent) = config_file.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error!(
            "Failed to create config directory {}: {e}",
            parent.display()
        );
        return;
    }
    if let Err(e) = std::fs::write(&config_file, config) {
        error!("Failed to write config file {}: {e}", config_file.display());
    }
    debug!("Saved config to: {:?}", config_file);
}

/// Launches a new tunnel instance. Binds the TCP listener, creates the tunnel
/// and pushes it into shared state. Returns the created instance data.
///
/// Fails when the local address is already taken by another instance, or when
/// a duplicate remote already exists for the same scope.
pub async fn launch_instance(
    state: &ServerState, instance_data: &InstanceData,
) -> Result<InstanceData, (axum::http::StatusCode, String)> {
    use labstreamgate::utils::create_tcp_listener;

    let remote_trimmed = instance_data.remote.trim();
    if !remote_trimmed.starts_with("ws://") && !remote_trimmed.starts_with("wss://") {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Remote address must use ws:// or wss://".to_string(),
        ));
    }

    let listener = create_tcp_listener(&instance_data.local).await?;

    let local = listener
        .local_addr()
        .expect("failed to bind port")
        .to_string();

    let scope = instance_data.scope_host.clone();

    let mut instances = state.instances.write().await;
    if instances.iter().any(|i| i.local.as_str() == local) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!("The local address {local} is already taken by another instance"),
        ));
    }

    // Reuse an existing instance when the same remote was already launched
    // within the same scope, only updating its label.
    if let Some(instance) = instances
        .iter_mut()
        .find(|i| i.remote == remote_trimmed && i.scope_host == scope)
    {
        if instance.label != instance_data.label {
            instance.label = instance_data.label.clone();
        }

        let data: InstanceData = (&*instance).into();
        drop(instances);
        state.events.send(UiEvent::Refresh).await.ok();
        return Ok(data);
    }

    let instance = ProxyInstance::new(
        instance_data.label.clone(),
        scope.clone(),
        instance_data.browser.clone(),
        listener,
        remote_trimmed,
    );

    let instance_resp: InstanceData = (&instance).into();
    instances.push(instance);
    drop(instances);

    let state_clone = state.clone();
    let instance = instance_resp.clone();
    tokio().spawn(async move {
        let client = reqwest::Client::new();
        match workers::update_instance_latency(&instance, &client).await {
            Ok(elapsed) => workers::update_instance_state(&state_clone, &instance, elapsed).await,
            Err(_) => workers::update_instance_state(&state_clone, &instance, -1).await,
        };
    });

    state.events.send(UiEvent::Refresh).await.ok();

    Ok(instance_resp)
}

/// Removes the instance whose local address matches `local`, if any.
pub async fn remove_instance(state: &ServerState, local: &str) -> bool {
    let mut instances = state.instances.write().await;
    let before = instances.len();
    instances.retain(|i| i.local.as_str() != local);
    let removed = instances.len() != before;
    drop(instances);

    if removed {
        state.events.send(UiEvent::Refresh).await.ok();
    }
    removed
}

/// Marks the scope `host` as allowed.
pub async fn allow_scope(state: &ServerState, scope_host: &str) {
    let mut scopes = state.scopes.write().await;
    if let Some(scope) = scopes.iter_mut().find(|s| s.host == scope_host) {
        scope.state = "allowed".to_string();
        info!("Scope {scope_host} allowed");
    }
    drop(scopes);

    persist_scopes(state).await;
    state.events.send(UiEvent::Refresh).await.ok();
}

/// Removes the scope `host` and all of its instances.
pub async fn remove_scope(state: &ServerState, scope_host: &str) {
    let removed_scope = {
        let mut scopes = state.scopes.write().await;
        scopes
            .iter()
            .position(|s| s.host == scope_host)
            .map(|index| scopes.remove(index))
    };

    match removed_scope {
        Some(scope) => {
            state
                .instances
                .write()
                .await
                .retain(|i| i.scope_host.as_str() != scope.host);

            info!("Scope {} removed", scope.host);
        }
        None => return,
    };

    persist_scopes(state).await;
    state.events.send(UiEvent::Refresh).await.ok();
}

pub fn default_label() -> String {
    format!("inst-{:06x}", rand::random::<u32>())
}

/// Returns a handle to the global tokio runtime, for spawning background work
/// from the UI thread.
pub fn tokio_handle() -> tokio::runtime::Handle {
    tokio().handle().clone()
}

pub use workers::system_info;
