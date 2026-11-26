use std::time::Duration;

use axum::{
    Json,
    body::Body,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{Span, debug, info, warn};

use super::{
    OFFICIAL_XUJCLAB_SCOPE_HOST, OFFICIAL_XUJCLAB_SCOPE_NAME, ServerState, UiEvent,
    canonical_scope_host, launch_instance,
};
use crate::{
    launcher,
    models::{FeatureFlags, InstanceData, ScopeData},
};

/// Deterministic candidate loopback ports tried in order so the browser client
/// can reliably discover LabStreamGate even when port 3307 is reserved by the OS.
pub const CANDIDATE_PORTS: &[u16] = &[3307, 3308, 3309, 13307, 23307];

async fn bind_controller_listener() -> tokio::net::TcpListener {
    for &candidate in CANDIDATE_PORTS {
        match tokio::net::TcpListener::bind(("127.0.0.1", candidate)).await {
            Ok(listener) => return listener,
            Err(e) => warn!("Failed to bind 127.0.0.1:{candidate}: {e}"),
        }
    }
    info!("All candidate ports busy; falling back to an ephemeral port...");
    tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind loopback port")
}

pub async fn serve(state: ServerState) {
    let listener = bind_controller_listener().await;
    let port = listener.local_addr().unwrap().port();

    *state.api_port.write().await = port;
    launcher::write_lock_file(port);

    state.events.send(UiEvent::Online { port }).await.ok();

    let app = router(state);

    // Best-effort IPv6 loopback listener on the same port so `http://localhost:<port>`
    // works even on systems where `localhost` resolves to `::1` first.
    if let Ok(v6_listener) = tokio::net::TcpListener::bind(("::1", port)).await {
        let v6_app = app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(v6_listener, v6_app).await;
        });
    }

    info!(
        "LabStreamGate controller is listening on [[ {} ]]",
        listener.local_addr().expect("failed to bind port")
    );
    axum::serve(listener, app)
        .await
        .expect("failed to launch server");
}

pub fn router(state: ServerState) -> axum::Router {
    let cors_state = state.clone();
    let scoped_cors_layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_private_network(true)
        .allow_origin(AllowOrigin::async_predicate(
            move |origin, _request_parts| {
                let cors_state = cors_state.clone();
                async move {
                    let Ok(origin_str) = origin.to_str() else {
                        return false;
                    };
                    let canonical = canonical_scope_host(origin_str);
                    if canonical.is_empty() {
                        return false;
                    }
                    let scopes = cors_state.scopes.read().await;
                    scopes
                        .iter()
                        .any(|scope| scope.host == canonical && scope.state == "allowed")
                }
            },
        ));

    // Handshake endpoints (`/version` and `/connect`) accept any browser Origin so
    // official routes (`ctf.xujclab.com`, `campus.xujclab.com:8798`, `edge-hk.xujclab.com:50412`),
    // emergency Cloudflare Quick Tunnels (`*.trycloudflare.com`), and local dev servers
    // can probe version and request user scope authorization cleanly.
    let handshake_cors_layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::OPTIONS])
        .allow_headers(Any)
        .allow_private_network(true)
        .allow_origin(AllowOrigin::mirror_request());

    axum::Router::new()
        .merge(
            axum::Router::new()
                .route(
                    "/pool",
                    get(get_instances).post(launch).delete(close_instance),
                )
                .route("/popup", post(popup_window))
                .layer(scoped_cors_layer)
                .with_state(state.clone()),
        )
        .merge(
            axum::Router::new()
                .route(
                    "/connect",
                    get(get_control_status)
                        .post(request_control)
                        .patch(update_website_info),
                )
                .route(
                    "/version",
                    get(|| async { Json(env!("CARGO_PKG_VERSION")) }),
                )
                .layer(handshake_cors_layer)
                .with_state(state.clone()),
        )
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
                .on_failure(())
                .on_response(|response: &Response, latency: Duration, _span: &Span| {
                    debug!(
                        "API Request [{}] in {}ms",
                        response.status(),
                        latency.as_millis()
                    );
                }),
        )
        .with_state::<()>(state)
}

#[derive(Serialize)]
struct InstanceResponse {
    label: String,
    remote: String,
    local: String,
    #[deprecated]
    from: String,
    #[deprecated]
    to: String,
    latency: i32,
}

impl From<&crate::daemon::ProxyInstance> for InstanceResponse {
    #[allow(deprecated)]
    fn from(instance: &crate::daemon::ProxyInstance) -> Self {
        InstanceResponse {
            label: instance.label.clone(),
            remote: instance.remote.clone(),
            local: instance.local.clone(),
            from: instance.local.clone(),
            to: instance.remote.clone(),
            latency: instance.latency,
        }
    }
}

async fn require_allowed_scope(
    state: &ServerState, headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let raw_origin = origin(headers);
    if raw_origin.is_empty() {
        // Non-browser loopback caller (e.g. local CLI / single-instance notifier).
        return Ok("default-scope".to_string());
    }
    let scope = canonical_scope_host(raw_origin);
    let scopes = state.scopes.read().await;
    match scopes.iter().find(|s| s.host == scope) {
        Some(found) if found.state == "allowed" => Ok(scope),
        Some(_) => Err((
            StatusCode::FORBIDDEN,
            format!("Scope {scope} is pending approval"),
        )),
        None => Err((StatusCode::FORBIDDEN, format!("Scope {scope} not found"))),
    }
}

async fn get_instances(
    State(state): State<ServerState>, headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = require_allowed_scope(&state, &headers).await?;
    let instances = state.instances.read().await;
    let instances: Vec<InstanceResponse> = instances
        .iter()
        .filter_map(|instance| {
            if instance.scope_host.as_str() == scope {
                Some(instance.into())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    Ok(Json(instances))
}

async fn launch(
    State(state): State<ServerState>, headers: HeaderMap,
    axum::Json(mut instance_data): axum::Json<InstanceData>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = require_allowed_scope(&state, &headers).await?;
    instance_data.scope_host = scope;

    // External browser scopes may only bind loopback interfaces (`127.0.0.1` / `localhost`).
    if instance_data.scope_host != "default-scope" {
        let local_host = instance_data
            .local
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(instance_data.local.as_str());
        if local_host != "127.0.0.1" && local_host != "localhost" {
            instance_data.local = "127.0.0.1:0".to_string();
        }
    }

    launch_instance(&state, &instance_data).await.map(Json)
}

#[derive(Deserialize)]
struct CloseInstanceRequest {
    #[serde(alias = "key")]
    pub local: String,
}

async fn close_instance(
    State(state): State<ServerState>, headers: HeaderMap,
    axum::Json(req): axum::Json<CloseInstanceRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = require_allowed_scope(&state, &headers).await?;

    let local = req.local.clone();
    let instances = state.instances.write().await;

    let Some(tunnel) = instances.iter().find(|i| i.local.as_str() == local) else {
        return Err((StatusCode::BAD_REQUEST, format!("Tunnel {local} not found")));
    };

    if tunnel.scope_host.as_str() != scope {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Tunnel {local} not found in scope {scope}"),
        ));
    }

    drop(instances);
    super::remove_instance(&state, &local).await;

    Ok(StatusCode::OK)
}

async fn get_control_status(
    State(state): State<ServerState>, headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let req_scope = canonical_scope_host(origin(&headers));
    let scopes = state.scopes.read().await;
    let scope = scopes.iter().find(|s| s.host == req_scope);
    if let Some(scope) = scope {
        if scope.state == "pending" {
            Ok(StatusCode::CREATED)
        } else {
            Ok(StatusCode::ACCEPTED)
        }
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("Scope {req_scope} not found"),
        ))
    }
}

async fn request_control(
    State(state): State<ServerState>, headers: HeaderMap, req: Request<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let req_scope = canonical_scope_host(origin(&headers));
    if req_scope.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Missing Origin header".to_string()));
    }
    let json_body = axum::Json::<ScopeData>::from_request(req, &state)
        .await
        .ok();
    let (scope_name, scope_features, scope_settings) = if let Some(Json(ScopeData {
        name,
        features,
        settings,
        ..
    })) = json_body
    {
        (name, features, settings)
    } else {
        (req_scope.clone(), FeatureFlags::Basic, Default::default())
    };

    let mut scopes = state.scopes.write().await;
    if let Some(existing) = scopes.iter().find(|scope| scope.host == req_scope) {
        let is_pending = existing.state == "pending";
        drop(scopes);
        if is_pending {
            state.events.send(UiEvent::Popup).await.ok();
            return Ok(StatusCode::CREATED);
        }
        return Ok(StatusCode::ACCEPTED);
    }

    let is_official = req_scope == OFFICIAL_XUJCLAB_SCOPE_HOST;
    let resolved_name = if is_official {
        OFFICIAL_XUJCLAB_SCOPE_NAME.to_string()
    } else if scope_name.is_empty() {
        req_scope.clone()
    } else {
        scope_name
    };
    let initial_state = if is_official { "allowed" } else { "pending" };
    let scope = ScopeData {
        name: resolved_name,
        host: req_scope.clone(),
        state: initial_state.to_string(),
        features: scope_features,
        settings: scope_settings,
    };
    scopes.push(scope);
    drop(scopes);

    debug!(
        "Scope {} registered with state={}",
        req_scope, initial_state
    );
    super::persist_scopes(&state).await;
    state.events.send(UiEvent::Refresh).await.ok();
    if initial_state == "pending" {
        state.events.send(UiEvent::Popup).await.ok();
    }

    Ok(if initial_state == "allowed" {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    })
}

async fn update_website_info(
    State(state): State<ServerState>, headers: HeaderMap,
    axum::Json(scope_data): axum::Json<ScopeData>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let req_scope = canonical_scope_host(origin(&headers));
    let mut scopes = state.scopes.write().await;
    if let Some(scope) = scopes.iter_mut().find(|s| s.host == req_scope) {
        scope.name = scope_data.name.clone();
        scope.features = scope_data.features;
        scope.settings = scope_data.settings.clone();
        drop(scopes);

        super::persist_scopes(&state).await;
        state.events.send(UiEvent::Refresh).await.ok();

        Ok(StatusCode::OK)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("Scope {req_scope} not found"),
        ))
    }
}

async fn popup_window(State(state): State<ServerState>) -> impl IntoResponse {
    state.events.send(UiEvent::Popup).await.ok();
    StatusCode::OK
}

fn origin(headers: &HeaderMap) -> &str {
    headers
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{is_official_xujclab_origin, normalize_scopes};
    use std::collections::HashMap;

    #[test]
    fn recognizes_all_official_xujclab_domains_and_ports() {
        assert!(is_official_xujclab_origin("https://ctf.xujclab.com"));
        assert!(is_official_xujclab_origin(
            "https://campus.xujclab.com:8798"
        ));
        assert!(is_official_xujclab_origin(
            "https://edge-hk.xujclab.com:50412"
        ));
        assert!(is_official_xujclab_origin("https://xujclab.com"));
        assert!(is_official_xujclab_origin("https://new.xujclab.com"));

        assert!(!is_official_xujclab_origin("http://ctf.xujclab.com"));
        assert!(!is_official_xujclab_origin("https://evilxujclab.com"));
        assert!(!is_official_xujclab_origin("https://xujclab.com.evil.com"));
        assert!(!is_official_xujclab_origin(
            "https://demo.trycloudflare.com"
        ));
    }

    #[test]
    fn canonicalizes_and_migrates_legacy_xujclab_scopes() {
        assert_eq!(
            canonical_scope_host("https://campus.xujclab.com:8798"),
            OFFICIAL_XUJCLAB_SCOPE_HOST
        );
        assert_eq!(
            canonical_scope_host("https://edge-hk.xujclab.com:50412"),
            OFFICIAL_XUJCLAB_SCOPE_HOST
        );
        assert_eq!(
            canonical_scope_host("https://demo.trycloudflare.com"),
            "https://demo.trycloudflare.com"
        );

        let migrated = normalize_scopes(vec![ScopeData {
            host: "https://new.xujclab.com".to_string(),
            name: "xujclab".to_string(),
            state: "allowed".to_string(),
            features: FeatureFlags::Basic,
            settings: HashMap::new(),
        }]);
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].host, OFFICIAL_XUJCLAB_SCOPE_HOST);
        assert_eq!(migrated[0].state, "allowed");
    }
}
