use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Body,
    extract::{
        ConnectInfo, FromRef, Path as AxumPath, Request as ExtractRequest, State, WebSocketUpgrade,
    },
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use labstreamgate::{
    ProxyStats, TrafficDirection, TrafficObserver,
    device::{DeviceMetadata, HEADER_DEVICE_ID, HEADER_DEVICE_INFO, parse_incoming_device},
    proxy_observed,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{Span, debug, error, info, warn};

use crate::cli::{
    capture::{
        CaptureSession, append_audit, default_capture_root, random_connection_id,
        spawn_retention_cleanup,
    },
    logger::init_logger,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Launch the platform tunnel gateway.
#[allow(clippy::too_many_arguments)]
pub async fn launch(
    host: Option<String>, port: Option<u16>, secret: Option<String>, state_file: Option<String>,
    allowed_target_hosts: Vec<String>, max_connections: usize, capture_root: Option<String>,
    max_capture_bytes: u64, capture_retention_days: u64, capture_max_total_bytes: u64,
    max_connections_per_tunnel: usize, connection_timeout_seconds: u64, log_json: Option<bool>,
) {
    init_logger(log_json.unwrap_or(false));

    let secret = secret
        .or_else(|| std::env::var("STREAMGATE_ADMIN_TOKEN").ok())
        .or_else(|| std::env::var("TUNNEL_GATEWAY_ADMIN_TOKEN").ok())
        .or_else(|| std::env::var("WSRX_ADMIN_TOKEN").ok());
    let Some(secret) = secret.filter(|value| value.len() >= 32) else {
        error!(
            "STREAMGATE_ADMIN_TOKEN (or TUNNEL_GATEWAY_ADMIN_TOKEN) must contain at least 32 characters; refusing to start"
        );
        return;
    };

    let allowed_target_hosts = parse_allowed_hosts(allowed_target_hosts);
    if allowed_target_hosts.is_empty() {
        error!("STREAMGATE_ALLOWED_TARGET_HOSTS must contain at least one explicit target host");
        return;
    }
    let state_file = state_file.map(PathBuf::from);
    let capture_root = capture_root
        .map(PathBuf::from)
        .unwrap_or_else(|| default_capture_root(state_file.as_deref()));
    let connections = Arc::new(RwLock::new(load_registry(state_file.as_deref()).await));
    let state = GlobalState {
        secret,
        connections,
        state_file,
        allowed_target_hosts: Arc::new(allowed_target_hosts),
        connection_slots: Arc::new(Semaphore::new(max_connections.max(1))),
        capture_root,
        max_capture_bytes,
        per_tunnel_connections: Arc::new(StdMutex::new(HashMap::new())),
        rejection_throttle: Arc::new(StdMutex::new(HashMap::new())),
        max_connections_per_tunnel: max_connections_per_tunnel.max(1),
        connection_timeout: Duration::from_secs(connection_timeout_seconds.max(1)),
        audit_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    spawn_expiry_cleanup(state.clone());
    spawn_retention_cleanup(
        state.capture_root.clone(),
        capture_retention_days,
        capture_max_total_bytes,
    );
    let router = build_router(state);
    let listener = TcpListener::bind(&format!(
        "{}:{}",
        host.unwrap_or(String::from("127.0.0.1")),
        port.unwrap_or(0)
    ))
    .await
    .expect("failed to bind port");
    info!(
        "LabStreamGate gateway is listening on {}",
        listener.local_addr().expect("failed to read bound port")
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("failed to launch server");
}

type TunnelRegistry = HashMap<String, TunnelRecord>;
type RegistryError = (StatusCode, String);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelRecord {
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    challenge_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    competition_id: Option<String>,
    #[serde(default)]
    capture: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_device_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_at: Option<u64>,
}

impl TunnelRecord {
    fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expiry| expiry <= now)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionAudit {
    connection_id: String,
    instance_id: String,
    challenge_id: String,
    user_id: String,
    competition_id: Option<String>,
    client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_summary: Option<String>,
    target: String,
    started_at: u128,
    ended_at: u128,
    client_to_target_bytes: u64,
    target_to_client_bytes: u64,
    result: String,
    capture_path: Option<String>,
    captured_bytes: u64,
    capture_truncated: bool,
}

struct ConnectionObserver {
    client_to_target: AtomicU64,
    target_to_client: AtomicU64,
    capture: Option<Arc<dyn TrafficObserver>>,
}

impl ConnectionObserver {
    fn new(capture: Option<Arc<dyn TrafficObserver>>) -> Self {
        Self {
            client_to_target: AtomicU64::new(0),
            target_to_client: AtomicU64::new(0),
            capture,
        }
    }

    fn stats(&self) -> ProxyStats {
        ProxyStats {
            client_to_target: self.client_to_target.load(Ordering::Relaxed),
            target_to_client: self.target_to_client.load(Ordering::Relaxed),
        }
    }
}

impl TrafficObserver for ConnectionObserver {
    fn observe(&self, direction: TrafficDirection, data: &[u8]) {
        match direction {
            TrafficDirection::ClientToTarget => {
                self.client_to_target
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            TrafficDirection::TargetToClient => {
                self.target_to_client
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        if let Some(capture) = &self.capture {
            capture.observe(direction, data);
        }
    }
}

fn classify_proxy_error(error: &str, stats: ProxyStats) -> String {
    if (stats.client_to_target > 0 || stats.target_to_client > 0)
        && error.contains("Connection reset without closing handshake")
    {
        "completed_ungraceful_close".into()
    } else {
        format!("proxy_error:{error}")
    }
}

#[derive(Clone, FromRef)]
pub struct GlobalState {
    pub secret: String,
    connections: Arc<RwLock<TunnelRegistry>>,
    state_file: Option<PathBuf>,
    allowed_target_hosts: Arc<HashSet<String>>,
    connection_slots: Arc<Semaphore>,
    capture_root: PathBuf,
    max_capture_bytes: u64,
    per_tunnel_connections: Arc<StdMutex<HashMap<String, usize>>>,
    rejection_throttle: Arc<StdMutex<HashMap<(String, String), u64>>>,
    max_connections_per_tunnel: usize,
    connection_timeout: Duration,
    audit_lock: Arc<tokio::sync::Mutex<()>>,
}

fn build_router(state: GlobalState) -> axum::Router {
    let management = axum::Router::new()
        .route(
            "/pool",
            get(get_tunnels).post(launch_tunnel).delete(close_tunnel),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authorize_management,
        ));

    axum::Router::new()
        .merge(management)
        .route("/health", get(health))
        .route("/{key}", get(process_traffic).options(ping))
        .route("/traffic/{*key}", get(process_traffic).options(ping))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    tracing::info_span!(
                        "http",
                        method = %request.method(),
                        uri = %request.uri().path(),
                    )
                })
                .on_request(())
                .on_response(|response: &Response, latency: Duration, _span: &Span| {
                    info!("[{}] in {}ms", response.status(), latency.as_millis());
                }),
        )
        .with_state(state)
}

async fn authorize_management(
    State(secret): State<String>, req: ExtractRequest, next: Next,
) -> Result<Response, StatusCode> {
    let supplied = req
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value));

    if supplied.is_some_and(|value| constant_time_eq(value.as_bytes(), secret.as_bytes())) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TunnelRequest {
    #[serde(alias = "from")]
    key: String,
    #[serde(alias = "to")]
    target: String,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    challenge_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    competition_id: Option<String>,
    #[serde(default)]
    capture: bool,
}

async fn launch_tunnel(
    State(state): State<GlobalState>, Json(req): Json<TunnelRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    validate_key(&req.key)?;
    validate_target(&req.target, &state.allowed_target_hosts)?;
    if req
        .expires_at
        .is_some_and(|expiry| expiry <= unix_timestamp())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "expiresAt must be in the future".into(),
        ));
    }

    let record = TunnelRecord {
        target: req.target,
        expires_at: req.expires_at,
        instance_id: req.instance_id,
        challenge_id: req.challenge_id,
        user_id: req.user_id,
        competition_id: req.competition_id,
        capture: req.capture,
        bound_device_id: None,
        bound_device_summary: None,
        bound_at: None,
    };
    let key = req.key;
    let saved = update_registry(&state, move |registry| {
        let mut next_record = record;
        let now = unix_timestamp();
        if let Some(existing) = registry.get(&key)
            && !existing.is_expired(now)
        {
            next_record.bound_device_id = existing.bound_device_id.clone();
            next_record.bound_device_summary = existing.bound_device_summary.clone();
            next_record.bound_at = existing.bound_at;
        }
        registry.insert(key, next_record.clone());
        Ok((next_record, true))
    })
    .await?;

    Ok((StatusCode::CREATED, Json(saved)))
}

async fn get_tunnels(State(state): State<GlobalState>) -> impl IntoResponse {
    remove_expired(&state).await;
    let now = unix_timestamp();
    let active: TunnelRegistry = state
        .connections
        .read()
        .await
        .iter()
        .filter(|(_, record)| !record.is_expired(now))
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect();
    Json(active)
}

#[derive(Deserialize)]
struct CloseTunnelRequest {
    #[serde(alias = "from")]
    key: String,
}

async fn close_tunnel(
    State(state): State<GlobalState>, Json(req): Json<CloseTunnelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    update_registry(&state, move |registry| {
        if registry.remove(&req.key).is_none() {
            return Err((StatusCode::NOT_FOUND, "tunnel not found".into()));
        }
        Ok(((), true))
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn process_traffic(
    State(state): State<GlobalState>, AxumPath(key): AxumPath<String>, headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>, ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let client = forwarded_client(&headers, peer);
    let device = extract_device(&headers, client);
    let record = bind_or_verify_device(&state, &key, client, &device).await?;
    let tunnel_permit = TunnelConnectionPermit::acquire(
        state.per_tunnel_connections.clone(),
        key.clone(),
        state.max_connections_per_tunnel,
    )?;
    let permit = state
        .connection_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway connection limit reached".into(),
            )
        })?;

    Ok(ws.on_upgrade(move |socket| async move {
        let _permit = permit;
        let _tunnel_permit = tunnel_permit;
        let connection_id = random_connection_id();
        let instance_id = resolve_audit_instance_id(&record, &key);
        let started_at = unix_timestamp_millis();
        let mut stats = ProxyStats::default();
        let mut result = "completed".to_string();
        let mut capture = None;

        let tcp = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&record.target)).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(err)) => {
                error!(target = %record.target, "failed to connect to tunnel target: {err}");
                result = format!("target_connect_failed:{err}");
                write_audit(
                    &state,
                    &record,
                    &instance_id,
                    &connection_id,
                    client,
                    &device,
                    started_at,
                    stats,
                    result,
                    None,
                    0,
                    false,
                )
                .await;
                return;
            }
            Err(_) => {
                error!(target = %record.target, "timed out connecting to tunnel target");
                result = "target_connect_timeout".into();
                write_audit(
                    &state,
                    &record,
                    &instance_id,
                    &connection_id,
                    client,
                    &device,
                    started_at,
                    stats,
                    result,
                    None,
                    0,
                    false,
                )
                .await;
                return;
            }
        };

        if record.capture {
            match CaptureSession::start(
                &state.capture_root,
                &instance_id,
                &connection_id,
                client,
                &record.target,
                state.max_capture_bytes,
            )
            .await
            {
                Ok(session) => capture = Some(session),
                Err(err) => error!("failed to start traffic capture: {err}"),
            }
        }

        // Write an immediate `active` audit entry so long-lived HTTP Keep-Alive or
        // interactive shell connections appear immediately in the admin panel.
        let initial_capture_path = capture
            .as_ref()
            .map(|session| session.relative_path.clone());
        write_audit_with_end(
            &state,
            &record,
            &instance_id,
            &connection_id,
            client,
            &device,
            started_at,
            0,
            ProxyStats::default(),
            "active".to_string(),
            initial_capture_path,
            0,
            false,
        )
        .await;

        let capture_observer = capture
            .as_ref()
            .map(|session| session.observer.clone() as Arc<dyn TrafficObserver>);
        let connection_observer = Arc::new(ConnectionObserver::new(capture_observer));
        let observer = Some(connection_observer.clone() as Arc<dyn TrafficObserver>);
        match timeout(
            state.connection_timeout,
            proxy_observed(socket.into(), tcp, CancellationToken::new(), observer),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                debug!(target = %record.target, "tunnel closed: {err}");
                result = classify_proxy_error(&err.to_string(), connection_observer.stats());
            }
            Err(_) => result = "connection_timeout".into(),
        }
        stats = connection_observer.stats();

        let (captured_bytes, capture_truncated, capture_path) = match &capture {
            Some(session) => {
                let (bytes, truncated) = session.finish().await;
                (bytes, truncated, Some(session.relative_path.clone()))
            }
            None => (0, false, None),
        };
        write_audit(
            &state,
            &record,
            &instance_id,
            &connection_id,
            client,
            &device,
            started_at,
            stats,
            result,
            capture_path,
            captured_bytes,
            capture_truncated,
        )
        .await;
    }))
}

fn resolve_audit_instance_id(record: &TunnelRecord, key: &str) -> String {
    if record.instance_id.is_empty() {
        key.chars().take(32).collect()
    } else {
        record.instance_id.clone()
    }
}

fn extract_device(headers: &HeaderMap, client: SocketAddr) -> DeviceMetadata {
    parse_incoming_device(
        header_str(headers, HEADER_DEVICE_ID),
        header_str(headers, HEADER_DEVICE_INFO),
        header_str(headers, "user-agent"),
        header_str(headers, "accept-language"),
        client.ip(),
    )
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

async fn bind_or_verify_device(
    state: &GlobalState, key: &str, client: SocketAddr, device: &DeviceMetadata,
) -> Result<TunnelRecord, (StatusCode, String)> {
    let current = active_record(state, key).await?;
    if current.bound_device_id.as_deref() == Some(device.device_id.as_str()) {
        return Ok(current);
    }
    if current.bound_device_id.is_some() {
        record_device_rejection(state, &current, key, client, device).await;
        return Err((
            StatusCode::FORBIDDEN,
            "tunnel is already bound to another device".into(),
        ));
    }

    let owned_key = key.to_owned();
    let device_id = device.device_id.clone();
    let device_summary = device.summary();
    let outcome = update_registry(state, move |registry| {
        let now = unix_timestamp();
        let Some(entry) = registry.get_mut(&owned_key) else {
            return Err((StatusCode::NOT_FOUND, "tunnel not found".into()));
        };
        if entry.is_expired(now) {
            registry.remove(&owned_key);
            return Ok((Err(None), true));
        }
        match entry.bound_device_id.as_deref() {
            None => {
                entry.bound_device_id = Some(device_id);
                entry.bound_device_summary = Some(device_summary);
                entry.bound_at = Some(now);
                Ok((Ok(entry.clone()), true))
            }
            Some(existing) if existing == device_id => Ok((Ok(entry.clone()), false)),
            Some(_) => Ok((Err(Some(entry.clone())), false)),
        }
    })
    .await?;

    match outcome {
        Ok(bound_record) => Ok(bound_record),
        Err(None) => Err((StatusCode::GONE, "tunnel expired".into())),
        Err(Some(conflicting)) => {
            record_device_rejection(state, &conflicting, key, client, device).await;
            Err((
                StatusCode::FORBIDDEN,
                "tunnel is already bound to another device".into(),
            ))
        }
    }
}

async fn record_device_rejection(
    state: &GlobalState, record: &TunnelRecord, key: &str, client: SocketAddr,
    device: &DeviceMetadata,
) {
    let now_sec = unix_timestamp();
    let should_log = if let Ok(mut throttle) = state.rejection_throttle.lock() {
        let map_key = (key.to_owned(), device.device_id.clone());
        match throttle.get(&map_key).copied() {
            Some(last) if now_sec.saturating_sub(last) < 3 => false,
            _ => {
                throttle.insert(map_key, now_sec);
                true
            }
        }
    } else {
        true
    };

    warn!(
        instance_id = %record.instance_id,
        client_ip = %client.ip(),
        attempted_device = %device.device_id,
        bound_device = ?record.bound_device_id,
        "rejected cross-device tunnel connection"
    );

    if should_log {
        let instance_id = resolve_audit_instance_id(record, key);
        let connection_id = random_connection_id();
        let now_ms = unix_timestamp_millis();
        write_audit_with_end(
            state,
            record,
            &instance_id,
            &connection_id,
            client,
            device,
            now_ms,
            now_ms,
            ProxyStats::default(),
            "rejected_device_mismatch".into(),
            None,
            0,
            false,
        )
        .await;
    }
}

struct TunnelConnectionPermit {
    counts: Arc<StdMutex<HashMap<String, usize>>>,
    key: String,
}

impl TunnelConnectionPermit {
    fn acquire(
        counts: Arc<StdMutex<HashMap<String, usize>>>, key: String, limit: usize,
    ) -> Result<Self, (StatusCode, String)> {
        let mut current = counts.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "connection counter unavailable".into(),
            )
        })?;
        let count = current.entry(key.clone()).or_default();
        if *count >= limit {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "tunnel connection limit reached".into(),
            ));
        }
        *count += 1;
        drop(current);
        Ok(Self { counts, key })
    }
}

impl Drop for TunnelConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock()
            && let Some(count) = counts.get_mut(&self.key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_audit(
    state: &GlobalState, record: &TunnelRecord, instance_id: &str, connection_id: &str,
    client: SocketAddr, device: &DeviceMetadata, started_at: u128, stats: ProxyStats,
    result: String, capture_path: Option<String>, captured_bytes: u64, capture_truncated: bool,
) {
    write_audit_with_end(
        state,
        record,
        instance_id,
        connection_id,
        client,
        device,
        started_at,
        unix_timestamp_millis(),
        stats,
        result,
        capture_path,
        captured_bytes,
        capture_truncated,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn write_audit_with_end(
    state: &GlobalState, record: &TunnelRecord, instance_id: &str, connection_id: &str,
    client: SocketAddr, device: &DeviceMetadata, started_at: u128, ended_at: u128,
    stats: ProxyStats, result: String, capture_path: Option<String>, captured_bytes: u64,
    capture_truncated: bool,
) {
    let non_empty = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
    let agent = match (non_empty(&device.client), non_empty(&device.browser)) {
        (Some(c), Some(b)) => Some(format!("{c} · {b}")),
        (Some(c), None) => Some(c),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    let audit = ConnectionAudit {
        connection_id: connection_id.into(),
        instance_id: instance_id.into(),
        challenge_id: record.challenge_id.clone(),
        user_id: record.user_id.clone(),
        competition_id: record.competition_id.clone(),
        client_ip: client.ip().to_string(),
        device_id: non_empty(&device.device_id),
        device_os: non_empty(&device.os),
        device_model: non_empty(&device.model),
        client_agent: agent,
        device_summary: non_empty(&device.summary()),
        target: record.target.clone(),
        started_at,
        ended_at,
        client_to_target_bytes: stats.client_to_target,
        target_to_client_bytes: stats.target_to_client,
        result,
        capture_path,
        captured_bytes,
        capture_truncated,
    };
    match serde_json::to_vec(&audit) {
        Ok(line) => {
            if let Err(err) =
                append_audit(&state.capture_root, &state.audit_lock, instance_id, &line).await
            {
                error!("failed to write connection audit: {err}");
            }
        }
        Err(err) => error!("failed to serialize connection audit: {err}"),
    }
}

fn forwarded_client(headers: &HeaderMap, peer: SocketAddr) -> SocketAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
        })
        .map(|ip| SocketAddr::new(ip, peer.port()))
        .unwrap_or(peer)
}

async fn ping(
    State(state): State<GlobalState>, AxumPath(key): AxumPath<String>, headers: HeaderMap,
) -> StatusCode {
    match active_record(&state, &key).await {
        Ok(record) => {
            if let Some(ref bound_id) = record.bound_device_id
                && let Some(req_id) = header_str(&headers, HEADER_DEVICE_ID)
                && !req_id.trim().eq_ignore_ascii_case(bound_id)
            {
                return StatusCode::FORBIDDEN;
            }
            StatusCode::OK
        }
        Err((status, _)) => status,
    }
}

async fn health(State(state): State<GlobalState>) -> impl IntoResponse {
    let now = unix_timestamp();
    Json(serde_json::json!({
        "status": "ok",
        "service": "labstreamgate",
        "activeTunnels": state.connections.read().await.values()
            .filter(|record| !record.is_expired(now))
            .count(),
        "availableConnections": state.connection_slots.available_permits(),
        "activeTunnelConnections": state.per_tunnel_connections.lock()
            .map(|counts| counts.values().sum::<usize>())
            .unwrap_or_default(),
    }))
}

async fn active_record(
    state: &GlobalState, key: &str,
) -> Result<TunnelRecord, (StatusCode, String)> {
    let record = state.connections.read().await.get(key).cloned();
    let Some(record) = record else {
        return Err((StatusCode::NOT_FOUND, "tunnel not found".into()));
    };
    if !record.is_expired(unix_timestamp()) {
        return Ok(record);
    }

    let key = key.to_owned();
    match update_registry(state, move |registry| match registry.get(&key) {
        Some(record) if !record.is_expired(unix_timestamp()) => Ok((Some(record.clone()), false)),
        Some(_) => {
            registry.remove(&key);
            Ok((None, true))
        }
        None => Ok((None, false)),
    })
    .await
    {
        Ok(Some(renewed)) => return Ok(renewed),
        Ok(None) => (),
        Err(err) => error!("failed to persist expired tunnel removal: {}", err.1),
    }
    Err((StatusCode::GONE, "tunnel expired".into()))
}

fn validate_key(key: &str) -> Result<(), (StatusCode, String)> {
    let valid = (16..=128).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "key must contain 16-128 URL-safe ASCII characters".into(),
        ))
    }
}

fn validate_target(
    target: &str, allowed_hosts: &HashSet<String>,
) -> Result<(), (StatusCode, String)> {
    let host = if let Ok(address) = SocketAddr::from_str(target) {
        address.ip().to_string()
    } else {
        let (host, port) = target.rsplit_once(':').ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "target must include a host and port".into(),
            )
        })?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            || port.parse::<u16>().is_err()
        {
            return Err((StatusCode::BAD_REQUEST, "invalid tunnel target".into()));
        }
        host.to_ascii_lowercase()
    };
    if !allowed_hosts.contains(&host) {
        return Err((StatusCode::FORBIDDEN, "target host is not allowed".into()));
    }
    Ok(())
}

fn parse_allowed_hosts(hosts: Vec<String>) -> HashSet<String> {
    hosts
        .into_iter()
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

async fn load_registry(path: Option<&Path>) -> TunnelRegistry {
    let Some(path) = path else {
        return HashMap::new();
    };
    match tokio::fs::read(path).await {
        Ok(data) => match serde_json::from_slice::<TunnelRegistry>(&data) {
            Ok(mut registry) => {
                let now = unix_timestamp();
                registry.retain(|_, record| !record.is_expired(now));
                info!(count = registry.len(), path = %path.display(), "restored tunnel registry");
                registry
            }
            Err(err) => {
                error!(path = %path.display(), "failed to parse tunnel registry: {err}");
                HashMap::new()
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(err) => {
            error!(path = %path.display(), "failed to read tunnel registry: {err}");
            HashMap::new()
        }
    }
}

async fn update_registry<T: Send + 'static>(
    state: &GlobalState,
    update: impl FnOnce(&mut TunnelRegistry) -> Result<(T, bool), RegistryError> + Send + 'static,
) -> Result<T, RegistryError> {
    let mut registry = state.connections.clone().write_owned().await;
    let Some(path) = state.state_file.clone() else {
        return update(&mut registry).map(|(result, _)| result);
    };

    // Keep both publications in the same task so a disconnected caller cannot split the commit.
    tokio::task::spawn_blocking(move || {
        let mut next = registry.clone();
        let (result, changed) = update(&mut next)?;
        if changed {
            persist_registry(&path, &next)?;
            *registry = next;
        }
        Ok(result)
    })
    .await
    .map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to update tunnel registry: {err}"),
        )
    })?
}

fn persist_registry(path: &Path, registry: &TunnelRegistry) -> Result<(), RegistryError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(internal_io_error)?;
    }
    let data = serde_json::to_vec(registry).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize tunnel registry: {err}"),
        )
    })?;
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    std::fs::write(&temporary, data).map_err(internal_io_error)?;
    std::fs::rename(&temporary, path).map_err(internal_io_error)
}

fn internal_io_error(err: std::io::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to persist tunnel registry: {err}"),
    )
}

async fn remove_expired(state: &GlobalState) {
    let now = unix_timestamp();
    if let Ok(mut throttle) = state.rejection_throttle.lock() {
        throttle.retain(|_, ts| now.saturating_sub(*ts) < 60);
    }
    if let Err(err) = update_registry(state, |registry| {
        let now = unix_timestamp();
        let before = registry.len();
        registry.retain(|_, record| !record.is_expired(now));
        Ok(((), registry.len() != before))
    })
    .await
    {
        error!("failed to persist tunnel cleanup: {}", err.1);
    }
}

fn spawn_expiry_cleanup(state: GlobalState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            remove_expired(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(state_file: PathBuf) -> GlobalState {
        GlobalState {
            secret: String::new(),
            connections: Arc::new(RwLock::new(TunnelRegistry::new())),
            capture_root: state_file.parent().unwrap().to_path_buf(),
            state_file: Some(state_file),
            allowed_target_hosts: Arc::new(parse_allowed_hosts(vec!["127.0.0.1".into()])),
            connection_slots: Arc::new(Semaphore::new(1)),
            max_capture_bytes: 0,
            per_tunnel_connections: Arc::new(StdMutex::new(HashMap::new())),
            rejection_throttle: Arc::new(StdMutex::new(HashMap::new())),
            max_connections_per_tunnel: 1,
            connection_timeout: Duration::from_secs(1),
            audit_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[tokio::test]
    async fn first_device_binds_tunnel_and_second_device_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("labstreamgate-dev-{}", random_connection_id()));
        let path = dir.join("registry.json");
        let state = test_state(path.clone());
        let key = "test-tunnel-device-lock-0001";
        let expires_at = unix_timestamp() + 600;

        let mut req = tunnel_request(key, expires_at);
        req.instance_id =
            "container:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into();
        launch_tunnel(State(state.clone()), Json(req))
            .await
            .unwrap();

        let dev_a = DeviceMetadata {
            device_id: "sg1_aaaaaaaaaaaaaaaa".into(),
            os: "macOS 15.3 (aarch64)".into(),
            model: "Mac14,15".into(),
            client: "Desktop 0.6.10".into(),
            browser: "Chrome 134".into(),
        };
        let dev_b = DeviceMetadata {
            device_id: "sg1_bbbbbbbbbbbbbbbb".into(),
            os: "Windows 11 Build 26100 (x86_64)".into(),
            model: "LENOVO 82Y9".into(),
            client: "Desktop 0.6.10".into(),
            browser: "Edge 134".into(),
        };
        let peer_a: SocketAddr = "203.0.113.10:50000".parse().unwrap();
        let peer_b: SocketAddr = "198.51.100.22:50001".parse().unwrap();

        let first = bind_or_verify_device(&state, key, peer_a, &dev_a)
            .await
            .unwrap();
        assert_eq!(
            first.bound_device_id.as_deref(),
            Some("sg1_aaaaaaaaaaaaaaaa")
        );

        // Subsequent connections from the same device succeed.
        let second = bind_or_verify_device(&state, key, peer_a, &dev_a)
            .await
            .unwrap();
        assert_eq!(
            second.bound_device_id.as_deref(),
            Some("sg1_aaaaaaaaaaaaaaaa")
        );

        // Any other device attempting to open the same WSS tunnel is rejected and audited.
        let rejected = bind_or_verify_device(&state, key, peer_b, &dev_b)
            .await
            .unwrap_err();
        assert_eq!(rejected.0, StatusCode::FORBIDDEN);

        // Renewing the container tunnel preserves the bound device.
        let mut renew_req = tunnel_request(key, expires_at + 600);
        renew_req.instance_id =
            "container:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into();
        launch_tunnel(State(state.clone()), Json(renew_req))
            .await
            .unwrap();

        let still_rejected = bind_or_verify_device(&state, key, peer_b, &dev_b)
            .await
            .unwrap_err();
        assert_eq!(still_rejected.0, StatusCode::FORBIDDEN);
        assert_eq!(
            load_registry(Some(&path)).await[key]
                .bound_device_id
                .as_deref(),
            Some("sg1_aaaaaaaaaaaaaaaa")
        );

        let audit_file = dir.join("audit").join(
            "container0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.jsonl",
        );
        let audit_content = tokio::fs::read_to_string(audit_file).await.unwrap();
        assert!(audit_content.contains("\"result\":\"rejected_device_mismatch\""));
        assert!(audit_content.contains("\"deviceId\":\"sg1_bbbbbbbbbbbbbbbb\""));
        assert!(audit_content.contains("LENOVO 82Y9"));

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    fn tunnel_request(key: &str, expires_at: u64) -> TunnelRequest {
        TunnelRequest {
            key: key.into(),
            target: "127.0.0.1:8080".into(),
            expires_at: Some(expires_at),
            instance_id: String::new(),
            challenge_id: String::new(),
            user_id: String::new(),
            competition_id: None,
            capture: false,
        }
    }

    #[tokio::test]
    async fn concurrent_tunnel_changes_survive_restart() {
        let dir = std::env::temp_dir().join(format!("labstreamgate-{}", random_connection_id()));
        let path = dir.join("registry.tmp");
        let state = test_state(path.clone());
        let expires_at = unix_timestamp() + 600;
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..12 {
            let state = state.clone();
            tasks.spawn(async move {
                launch_tunnel(
                    State(state),
                    Json(tunnel_request(
                        &format!("test-tunnel-{index:04}"),
                        expires_at,
                    )),
                )
                .await
                .unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(load_registry(Some(&path)).await.len(), 12);

        let renewed = expires_at + 600;
        let (renew_result, close_result) = tokio::join!(
            launch_tunnel(
                State(state.clone()),
                Json(tunnel_request("test-tunnel-0000", renewed))
            ),
            close_tunnel(
                State(state.clone()),
                Json(CloseTunnelRequest {
                    key: "test-tunnel-0001".into()
                })
            ),
        );
        renew_result.unwrap();
        assert_eq!(close_result.unwrap(), StatusCode::NO_CONTENT);

        let restored = load_registry(Some(&path)).await;
        assert_eq!(restored.len(), 11);
        assert_eq!(restored["test-tunnel-0000"].expires_at, Some(renewed));
        assert!(!restored.contains_key("test-tunnel-0001"));
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn failed_persistence_keeps_existing_tunnel() {
        let dir = std::env::temp_dir().join(format!("labstreamgate-{}", random_connection_id()));
        let path = dir.join("registry.json");
        let state = test_state(path.clone());
        let key = "test-tunnel-0000";
        let expires_at = unix_timestamp() + 600;
        launch_tunnel(State(state.clone()), Json(tunnel_request(key, expires_at)))
            .await
            .unwrap();

        tokio::fs::create_dir(dir.join("registry.json.tmp"))
            .await
            .unwrap();
        let renew = launch_tunnel(
            State(state.clone()),
            Json(tunnel_request(key, expires_at + 600)),
        )
        .await;
        let close = close_tunnel(
            State(state.clone()),
            Json(CloseTunnelRequest { key: key.into() }),
        )
        .await;
        assert_eq!(renew.err().unwrap().0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(close.unwrap_err().0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            active_record(&state, key).await.unwrap().expires_at,
            Some(expires_at)
        );
        assert_eq!(
            load_registry(Some(&path)).await[key].expires_at,
            Some(expires_at)
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[test]
    fn connection_observer_keeps_counts_for_failed_proxies() {
        let observer = ConnectionObserver::new(None);
        observer.observe(TrafficDirection::ClientToTarget, b"request");
        observer.observe(TrafficDirection::TargetToClient, b"response");

        assert_eq!(
            observer.stats(),
            ProxyStats {
                client_to_target: 7,
                target_to_client: 8,
            }
        );
    }

    #[test]
    fn reset_after_transfer_is_not_reported_as_failed_traffic() {
        let result = classify_proxy_error(
            "WebSocket protocol error: Connection reset without closing handshake",
            ProxyStats {
                client_to_target: 7,
                target_to_client: 8,
            },
        );

        assert_eq!(result, "completed_ungraceful_close");
    }
}
