use std::process;

use clap::Parser;
use rustls::crypto;
use tracing::{error, info, warn};

#[cfg(feature = "client")]
mod cli;

/// LabStreamGate is a controlled TCP-over-WebSocket gateway for CTF platforms.
#[derive(Parser)]
#[command(name = "labstreamgate", bin_name = "labstreamgate", version, about)]
enum StreamGateCli {
    #[clap(alias("d"))]
    /// Launch the local LabStreamGate desktop controller daemon.
    Daemon {
        #[clap(long)]
        /// The admin and ws http address to listen on.
        host: Option<String>,
        #[clap(short, long)]
        /// The admin and ws http port to listen on.
        port: Option<u16>,
        #[clap(short, long)]
        secret: Option<String>,
        /// Log in json format.
        #[clap(short, long)]
        log_json: Option<bool>,
        /// The heartbeat interval in seconds.
        /// If not set, the daemon will not automatically exit when heartbeat
        /// timeout.
        #[clap(long)]
        heartbeat: Option<u64>,
    },
    #[clap(alias("c"))]
    /// Launch a local TCP-to-LabStreamGate client.
    Connect {
        /// The address to connect to.
        address: String,
        #[clap(long)]
        /// The admin and ws http address to listen on.
        host: Option<String>,
        #[clap(short, long)]
        /// The admin and ws http port to listen on.
        port: Option<u16>,
        /// Log in json format.
        #[clap(short, long)]
        log_json: Option<bool>,
    },
    #[clap(alias("s"))]
    /// Launch the LabStreamGate platform gateway.
    Serve {
        #[clap(long)]
        /// The admin and ws http address to listen on.
        host: Option<String>,
        #[clap(short, long)]
        /// The admin and ws http port to listen on.
        port: Option<u16>,
        #[clap(short, long)]
        secret: Option<String>,
        /// Persist the platform tunnel registry to this JSON file.
        #[clap(long, env = "STREAMGATE_STATE_FILE")]
        state_file: Option<String>,
        /// Only allow tunnel targets on these IP addresses or hostnames. Repeat as needed.
        #[clap(
            long = "allow-target-host",
            env = "STREAMGATE_ALLOWED_TARGET_HOSTS",
            value_delimiter = ','
        )]
        allowed_target_hosts: Vec<String>,
        /// Maximum number of simultaneous WebSocket tunnel connections (default: 4096).
        #[clap(long, env = "STREAMGATE_MAX_CONNECTIONS")]
        max_connections: Option<usize>,
        /// Root directory for connection audit logs and optional PCAP files.
        #[clap(long, env = "STREAMGATE_CAPTURE_ROOT")]
        capture_root: Option<String>,
        /// Maximum captured payload bytes per connection (default: 67108864).
        #[clap(long, env = "STREAMGATE_MAX_CAPTURE_BYTES")]
        max_capture_bytes: Option<u64>,
        /// Number of days to retain PCAP files (default: 7).
        #[clap(long, env = "STREAMGATE_CAPTURE_RETENTION_DAYS")]
        capture_retention_days: Option<u64>,
        /// Maximum total bytes retained across all PCAP files (default: 21474836480).
        #[clap(long, env = "STREAMGATE_CAPTURE_MAX_TOTAL_BYTES")]
        capture_max_total_bytes: Option<u64>,
        /// Maximum simultaneous connections for one tunnel (default: 32).
        #[clap(long, env = "STREAMGATE_MAX_CONNECTIONS_PER_TUNNEL")]
        max_connections_per_tunnel: Option<usize>,
        /// Maximum lifetime of one proxied connection in seconds (default: 1800).
        #[clap(long, env = "STREAMGATE_CONNECTION_TIMEOUT_SECONDS")]
        connection_timeout_seconds: Option<u64>,
        /// Log in json format.
        #[clap(short, long)]
        log_json: Option<bool>,
    },
}

#[cfg(feature = "client")]
fn legacy_env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok()?.trim().parse::<T>().ok()
}

#[tokio::main]
async fn main() {
    let cli = StreamGateCli::parse();
    match crypto::aws_lc_rs::default_provider().install_default() {
        Ok(_) => info!("using `AWS Libcrypto` as default crypto backend."),
        Err(err) => {
            error!("`AWS Libcrypto` is not available: {:?}", err);
            warn!("try to use `ring` as default crypto backend.");
            crypto::ring::default_provider()
                .install_default()
                .inspect_err(|err| {
                    error!("`ring` is not available: {:?}", err);
                    error!("All crypto backend are not available, exiting...");
                    process::exit(1);
                })
                .ok();
            info!("using `ring` as default crypto backend.");
        }
    }
    #[cfg(feature = "client")]
    match cli {
        StreamGateCli::Daemon {
            host,
            port,
            secret,
            log_json,
            heartbeat,
        } => cli::daemon::launch(host, port, secret, log_json, heartbeat).await,
        StreamGateCli::Connect {
            address,
            host,
            port,
            log_json,
        } => cli::connect::launch(address, host, port, log_json).await,
        StreamGateCli::Serve {
            host,
            port,
            secret,
            state_file,
            allowed_target_hosts,
            max_connections,
            capture_root,
            max_capture_bytes,
            capture_retention_days,
            capture_max_total_bytes,
            max_connections_per_tunnel,
            connection_timeout_seconds,
            log_json,
        } => {
            let state_file = state_file.or_else(|| std::env::var("WSRX_STATE_FILE").ok());
            let allowed_target_hosts = if allowed_target_hosts.is_empty() {
                std::env::var("WSRX_ALLOWED_TARGET_HOSTS")
                    .ok()
                    .map(|raw| raw.split(',').map(str::to_owned).collect())
                    .unwrap_or_default()
            } else {
                allowed_target_hosts
            };
            let max_connections = max_connections
                .or_else(|| legacy_env_parse("WSRX_MAX_CONNECTIONS"))
                .unwrap_or(4096);
            let capture_root = capture_root.or_else(|| std::env::var("WSRX_CAPTURE_ROOT").ok());
            let max_capture_bytes = max_capture_bytes
                .or_else(|| legacy_env_parse("WSRX_MAX_CAPTURE_BYTES"))
                .unwrap_or(67_108_864);
            let capture_retention_days = capture_retention_days
                .or_else(|| legacy_env_parse("WSRX_CAPTURE_RETENTION_DAYS"))
                .unwrap_or(7);
            let capture_max_total_bytes = capture_max_total_bytes
                .or_else(|| legacy_env_parse("WSRX_CAPTURE_MAX_TOTAL_BYTES"))
                .unwrap_or(21_474_836_480);
            let max_connections_per_tunnel = max_connections_per_tunnel
                .or_else(|| legacy_env_parse("WSRX_MAX_CONNECTIONS_PER_TUNNEL"))
                .unwrap_or(32);
            let connection_timeout_seconds = connection_timeout_seconds
                .or_else(|| legacy_env_parse("WSRX_CONNECTION_TIMEOUT_SECONDS"))
                .unwrap_or(1800);

            cli::serve::launch(
                host,
                port,
                secret,
                state_file,
                allowed_target_hosts,
                max_connections,
                capture_root,
                max_capture_bytes,
                capture_retention_days,
                capture_max_total_bytes,
                max_connections_per_tunnel,
                connection_timeout_seconds,
                log_json,
            )
            .await
        }
    }
    #[cfg(not(feature = "client"))]
    error!("LabStreamGate client feature is not enabled.");
}
