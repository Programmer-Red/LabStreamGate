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
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{Span, debug, error, info};
use wsrx::{ProxyStats, TrafficDirection, TrafficObserver, proxy_observed};

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
        .or_else(|| std::env::var("WSRX_ADMIN_TOKEN").ok())
        .or_else(|| std::env::var("TUNNEL_GATEWAY_ADMIN_TOKEN").ok());
    let Some(secret) = secret.filter(|value| value.len() >= 32) else {
        error!("WSRX_ADMIN_TOKEN must contain at least 32 characters; refusing to start");
        return;
    };

    let allowed_target_hosts = parse_allowed_hosts(allowed_target_hosts);
    if allowed_target_hosts.is_empty() {
        error!("WSRX_ALLOWED_TARGET_HOSTS must contain at least one explicit target host");
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

type ConnectionMap = Arc<RwLock<HashMap<String, TunnelRecord>>>;

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
    connections: ConnectionMap,
    state_file: Option<PathBuf>,
    allowed_target_hosts: Arc<HashSet<String>>,
    connection_slots: Arc<Semaphore>,
    capture_root: PathBuf,
    max_capture_bytes: u64,
    per_tunnel_connections: Arc<StdMutex<HashMap<String, usize>>>,
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
    };
    state
        .connections
        .write()
        .await
        .insert(req.key.clone(), record.clone());
    persist_registry(&state).await?;

    Ok((StatusCode::CREATED, Json(record)))
}

async fn get_tunnels(State(state): State<GlobalState>) -> impl IntoResponse {
    remove_expired(&state).await;
    Json(state.connections.read().await.clone())
}

#[derive(Deserialize)]
struct CloseTunnelRequest {
    #[serde(alias = "from")]
    key: String,
}

async fn close_tunnel(
    State(state): State<GlobalState>, Json(req): Json<CloseTunnelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if state.connections.write().await.remove(&req.key).is_none() {
        return Err((StatusCode::NOT_FOUND, "tunnel not found".into()));
    }
    persist_registry(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn process_traffic(
    State(state): State<GlobalState>, AxumPath(key): AxumPath<String>, headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>, ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let record = active_record(&state, &key).await?;
    let client = forwarded_client(&headers, peer);
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
        let instance_id = if record.instance_id.is_empty() {
            key.chars().take(32).collect()
        } else {
            record.instance_id.clone()
        };
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
    client: SocketAddr, started_at: u128, stats: ProxyStats, result: String,
    capture_path: Option<String>, captured_bytes: u64, capture_truncated: bool,
) {
    let audit = ConnectionAudit {
        connection_id: connection_id.into(),
        instance_id: instance_id.into(),
        challenge_id: record.challenge_id.clone(),
        user_id: record.user_id.clone(),
        competition_id: record.competition_id.clone(),
        client_ip: client.ip().to_string(),
        target: record.target.clone(),
        started_at,
        ended_at: unix_timestamp_millis(),
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
        .map(|ip| SocketAddr::new(ip, peer.port()))
        .unwrap_or(peer)
}

async fn ping(State(state): State<GlobalState>, AxumPath(key): AxumPath<String>) -> StatusCode {
    match active_record(&state, &key).await {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => status,
    }
}

async fn health(State(state): State<GlobalState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "labstreamgate",
        "activeTunnels": state.connections.read().await.len(),
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
    match record {
        Some(record) if !record.is_expired(unix_timestamp()) => Ok(record),
        Some(_) => {
            state.connections.write().await.remove(key);
            if let Err(err) = persist_registry(state).await {
                error!("failed to persist expired tunnel removal: {}", err.1);
            }
            Err((StatusCode::GONE, "tunnel expired".into()))
        }
        None => Err((StatusCode::NOT_FOUND, "tunnel not found".into())),
    }
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

async fn load_registry(path: Option<&Path>) -> HashMap<String, TunnelRecord> {
    let Some(path) = path else {
        return HashMap::new();
    };
    match tokio::fs::read(path).await {
        Ok(data) => match serde_json::from_slice::<HashMap<String, TunnelRecord>>(&data) {
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

async fn persist_registry(state: &GlobalState) -> Result<(), (StatusCode, String)> {
    let Some(path) = &state.state_file else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(internal_io_error)?;
    }
    let data = {
        let registry = state.connections.read().await;
        serde_json::to_vec(&*registry).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize tunnel registry: {err}"),
            )
        })?
    };
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, data)
        .await
        .map_err(internal_io_error)?;
    tokio::fs::rename(&temporary, path)
        .await
        .map_err(internal_io_error)
}

fn internal_io_error(err: std::io::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to persist tunnel registry: {err}"),
    )
}

async fn remove_expired(state: &GlobalState) {
    let now = unix_timestamp();
    let removed = {
        let mut registry = state.connections.write().await;
        let before = registry.len();
        registry.retain(|_, record| !record.is_expired(now));
        registry.len() != before
    };
    if removed && let Err(err) = persist_registry(state).await {
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
