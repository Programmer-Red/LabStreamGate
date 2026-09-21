use std::{sync::Arc, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use url::Url;
use wsrx::proxy;

use crate::cli::logger::init_logger;

pub async fn launch(
    address: String, host: Option<String>, port: Option<u16>, log_json: Option<bool>,
) {
    let log_json = log_json.unwrap_or(false);
    init_logger(log_json);
    let Ok(parsed_url) = Url::parse(&address) else {
        eprintln!("连接地址无效，请粘贴题目页提供的完整 ws:// 或 wss:// 地址。");
        return;
    };
    if parsed_url.scheme() != "ws" && parsed_url.scheme() != "wss" {
        eprintln!("连接地址协议无效，只支持 ws:// 或 wss://。");
        return;
    }

    let port = port.unwrap_or(0);
    let host = host.unwrap_or(String::from("127.0.0.1"));
    let listener = match TcpListener::bind(format!("{host}:{port}")).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("无法创建本地监听地址 {host}:{port}：{err}");
            return;
        }
    };
    let local_addr = listener
        .local_addr()
        .expect("failed to read local listener address");
    let url = parsed_url.as_ref().to_string();

    println!("LabStreamGate CLI 已启动");
    println!("本地连接地址：{local_addr}");
    println!("远端通道：{url}");
    println!("请保持此进程运行，并让浏览器、nc、SSH 或调试器连接上面的本地地址。");
    println!("无需使用 sudo；按 Ctrl+C 退出。\n");
    info!(local = %local_addr, remote = %url, "local tunnel listener started");

    let token = CancellationToken::new();
    let url = Arc::new(url);

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    error!("failed to listen for Ctrl+C: {err}");
                }
                println!("\nLabStreamGate CLI 已退出。");
                token.cancel();
                return;
            }
        };
        let (tcp, peer_addr) = match accepted {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("本地监听失败，LabStreamGate CLI 已退出：{err}");
                token.cancel();
                return;
            }
        };

        if token.is_cancelled() {
            return;
        }

        let url = url.clone();
        println!("收到本地连接 {peer_addr}，正在连接远端通道……");
        info!(remote = %url, peer = %peer_addr, "opening remote tunnel connection");

        let token = token.clone();
        tokio::spawn(async move {
            match proxy_ws_addr(url.as_ref(), tcp, token).await {
                Ok(_) => println!("本地连接 {peer_addr} 已关闭。"),
                Err(e) => {
                    eprintln!("连接远端通道失败（本地连接 {peer_addr}）：{e}");
                    debug!(peer = %peer_addr, error = %e, "TCP connection closed with error");
                }
            }
        });
    }
}

async fn proxy_ws_addr(
    addr: impl AsRef<str>, tcp: TcpStream, token: CancellationToken,
) -> Result<(), wsrx::Error> {
    let peer_addr = tcp.peer_addr().unwrap();
    let (ws, _) = timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async(addr.as_ref()),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "连接远端通道超时（15 秒）")
    })??;
    proxy(ws.into(), tcp, token).await?;
    info!(peer = %peer_addr, "remote tunnel connection closed");
    Ok(())
}
