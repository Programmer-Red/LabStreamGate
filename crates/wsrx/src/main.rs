use std::process;

use clap::Parser;
use rustls::crypto;
use tracing::{error, info, warn};

#[cfg(feature = "client")]
mod cli;

/// LabStreamGate is a controlled TCP-over-WebSocket gateway for CTF platforms.
#[derive(Parser)]
#[command(name = "labstreamgate", bin_name = "labstreamgate", version, about)]
enum WsrxCli {
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
        #[clap(long, env = "WSRX_STATE_FILE")]
        state_file: Option<String>,
        /// Only allow tunnel targets on these IP addresses. Repeat as needed.
        #[clap(
            long = "allow-target-host",
            env = "WSRX_ALLOWED_TARGET_HOSTS",
            value_delimiter = ','
        )]
        allowed_target_hosts: Vec<String>,
        /// Maximum number of simultaneous WebSocket tunnel connections.
        #[clap(long, env = "WSRX_MAX_CONNECTIONS", default_value_t = 4096)]
        max_connections: usize,
        /// Root directory for connection audit logs and optional PCAP files.
        #[clap(long, env = "WSRX_CAPTURE_ROOT")]
        capture_root: Option<String>,
        /// Maximum captured payload bytes per connection.
        #[clap(long, env = "WSRX_MAX_CAPTURE_BYTES", default_value_t = 67_108_864)]
        max_capture_bytes: u64,
        /// Number of days to retain PCAP files.
        #[clap(long, env = "WSRX_CAPTURE_RETENTION_DAYS", default_value_t = 7)]
        capture_retention_days: u64,
        /// Maximum total bytes retained across all PCAP files.
        #[clap(
            long,
            env = "WSRX_CAPTURE_MAX_TOTAL_BYTES",
            default_value_t = 21_474_836_480
        )]
        capture_max_total_bytes: u64,
        /// Maximum simultaneous connections for one tunnel.
        #[clap(long, env = "WSRX_MAX_CONNECTIONS_PER_TUNNEL", default_value_t = 32)]
        max_connections_per_tunnel: usize,
        /// Maximum lifetime of one proxied connection in seconds.
        #[clap(long, env = "WSRX_CONNECTION_TIMEOUT_SECONDS", default_value_t = 1800)]
        connection_timeout_seconds: u64,
        /// Log in json format.
        #[clap(short, long)]
        log_json: Option<bool>,
    },
}

#[tokio::main]
async fn main() {
    let cli = WsrxCli::parse();
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
        WsrxCli::Daemon {
            host,
            port,
            secret,
            log_json,
            heartbeat,
        } => cli::daemon::launch(host, port, secret, log_json, heartbeat).await,
        WsrxCli::Connect {
            address,
            host,
            port,
            log_json,
        } => cli::connect::launch(address, host, port, log_json).await,
        WsrxCli::Serve {
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
    error!("wsrx client is not enabled.");
}
