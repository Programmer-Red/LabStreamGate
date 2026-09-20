use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::{Mutex, mpsc, oneshot},
};
use tracing::error;
use wsrx::{TrafficDirection, TrafficObserver};

enum CaptureMessage {
    Packet(TrafficDirection, Vec<u8>, SystemTime),
    Finish(oneshot::Sender<()>),
}

pub struct CaptureObserver {
    sender: mpsc::Sender<CaptureMessage>,
    captured: AtomicU64,
    truncated: AtomicBool,
    max_bytes: u64,
}

impl TrafficObserver for CaptureObserver {
    fn observe(&self, direction: TrafficDirection, data: &[u8]) {
        let already = self.captured.load(Ordering::Relaxed);
        if already >= self.max_bytes {
            self.truncated.store(true, Ordering::Relaxed);
            return;
        }
        let remaining = (self.max_bytes - already) as usize;
        let length = remaining.min(data.len());
        if length < data.len() {
            self.truncated.store(true, Ordering::Relaxed);
        }
        let packet = data[..length].to_vec();
        if self
            .sender
            .try_send(CaptureMessage::Packet(direction, packet, SystemTime::now()))
            .is_ok()
        {
            self.captured.fetch_add(length as u64, Ordering::Relaxed);
        } else {
            self.truncated.store(true, Ordering::Relaxed);
        }
    }
}

pub struct CaptureSession {
    pub observer: Arc<CaptureObserver>,
    pub relative_path: String,
}

impl CaptureSession {
    pub async fn start(
        root: &Path, instance_id: &str, connection_id: &str, client: SocketAddr, target: &str,
        max_bytes: u64,
    ) -> std::io::Result<Self> {
        let safe_instance = safe_segment(instance_id);
        let relative_path = format!("captures/{safe_instance}/{connection_id}.pcap");
        let path = root.join(&relative_path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = File::create(path).await?;
        write_global_header(&mut file).await?;
        let (sender, receiver) = mpsc::channel(1024);
        tokio::spawn(write_capture(receiver, file, client, target.to_owned()));
        Ok(Self {
            observer: Arc::new(CaptureObserver {
                sender,
                captured: AtomicU64::new(0),
                truncated: AtomicBool::new(false),
                max_bytes,
            }),
            relative_path,
        })
    }

    pub async fn finish(&self) -> (u64, bool) {
        let (done_tx, done_rx) = oneshot::channel();
        let _ = self
            .observer
            .sender
            .send(CaptureMessage::Finish(done_tx))
            .await;
        let _ = done_rx.await;
        (
            self.observer.captured.load(Ordering::Relaxed),
            self.observer.truncated.load(Ordering::Relaxed),
        )
    }
}

async fn write_capture(
    mut receiver: mpsc::Receiver<CaptureMessage>, mut file: File, client: SocketAddr,
    target: String,
) {
    let target_port = target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(0);
    let client_ip = ipv4_or_documentation(client.ip(), Ipv4Addr::new(192, 0, 2, 1));
    let target_ip = target
        .parse::<SocketAddr>()
        .map(|address| ipv4_or_documentation(address.ip(), Ipv4Addr::new(192, 0, 2, 2)))
        .unwrap_or(Ipv4Addr::new(192, 0, 2, 2));

    while let Some(message) = receiver.recv().await {
        match message {
            CaptureMessage::Packet(direction, data, timestamp) => {
                let (source_ip, source_port, dest_ip, dest_port) = match direction {
                    TrafficDirection::ClientToTarget => {
                        (client_ip, client.port(), target_ip, target_port)
                    }
                    TrafficDirection::TargetToClient => {
                        (target_ip, target_port, client_ip, client.port())
                    }
                };
                for chunk in data.chunks(65_507) {
                    let packet =
                        build_udp_packet(source_ip, source_port, dest_ip, dest_port, chunk);
                    if let Err(err) = write_packet(&mut file, timestamp, &packet).await {
                        error!("failed to write pcap packet: {err}");
                        break;
                    }
                }
            }
            CaptureMessage::Finish(done) => {
                let _ = file.flush().await;
                let _ = done.send(());
                break;
            }
        }
    }
}

pub async fn append_audit(
    root: &Path, lock: &Mutex<()>, instance_id: &str, line: &[u8],
) -> std::io::Result<()> {
    let _guard = lock.lock().await;
    let directory = root.join("audit");
    tokio::fs::create_dir_all(&directory).await?;
    let path = directory.join(format!("{}.jsonl", safe_segment(instance_id)));
    if tokio::fs::metadata(&path)
        .await
        .map(|metadata| metadata.len() >= 16 * 1024 * 1024)
        .unwrap_or(false)
    {
        let rotated = path.with_extension("jsonl.1");
        let _ = tokio::fs::remove_file(&rotated).await;
        tokio::fs::rename(&path, rotated).await?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(line).await?;
    file.write_all(b"\n").await?;
    file.flush().await
}

fn safe_segment(value: &str) -> String {
    let value: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(128)
        .collect();
    if value.is_empty() {
        "unknown".into()
    } else {
        value
    }
}

async fn write_global_header(file: &mut File) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    header.extend_from_slice(&2_u16.to_le_bytes());
    header.extend_from_slice(&4_u16.to_le_bytes());
    header.extend_from_slice(&0_i32.to_le_bytes());
    header.extend_from_slice(&0_u32.to_le_bytes());
    header.extend_from_slice(&65_535_u32.to_le_bytes());
    header.extend_from_slice(&1_u32.to_le_bytes());
    file.write_all(&header).await
}

async fn write_packet(
    file: &mut File, timestamp: SystemTime, packet: &[u8],
) -> std::io::Result<()> {
    let timestamp = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&(timestamp.as_secs() as u32).to_le_bytes());
    header.extend_from_slice(&timestamp.subsec_micros().to_le_bytes());
    header.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    header.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    file.write_all(&header).await?;
    file.write_all(packet).await
}

fn build_udp_packet(
    source_ip: Ipv4Addr, source_port: u16, dest_ip: Ipv4Addr, dest_port: u16, payload: &[u8],
) -> Vec<u8> {
    let ip_length = 20 + 8 + payload.len();
    let mut packet = vec![0_u8; 14 + ip_length];
    packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut packet[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_length as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&dest_ip.octets());
    let checksum = ipv4_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp = &mut packet[34..42];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dest_port.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[42..].copy_from_slice(payload);
    packet
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for word in header.chunks_exact(2) {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_or_documentation(address: IpAddr, fallback: Ipv4Addr) -> Ipv4Addr {
    match address {
        IpAddr::V4(address) => address,
        IpAddr::V6(address) => address.to_ipv4_mapped().unwrap_or(fallback),
    }
}

pub fn random_connection_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

pub fn default_capture_root(state_file: Option<&Path>) -> PathBuf {
    state_file
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/var/lib/labstreamgate"))
        .to_path_buf()
}

pub fn spawn_retention_cleanup(root: PathBuf, retention_days: u64, max_total_bytes: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let root = root.clone();
            if let Err(err) = tokio::task::spawn_blocking(move || {
                cleanup_capture_files(&root, retention_days, max_total_bytes)
            })
            .await
            {
                error!("capture retention worker failed: {err}");
            }
        }
    });
}

fn cleanup_capture_files(
    root: &Path, retention_days: u64, max_total_bytes: u64,
) -> std::io::Result<()> {
    let capture_root = root.join("captures");
    let mut files = Vec::new();
    collect_pcaps(&capture_root, &mut files)?;
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(
            retention_days.saturating_mul(86_400),
        ))
        .unwrap_or(UNIX_EPOCH);
    for (path, modified, _) in &files {
        if *modified < cutoff {
            let _ = std::fs::remove_file(path);
        }
    }

    files.retain(|(path, _, _)| path.exists());
    files.sort_by_key(|(_, modified, _)| *modified);
    let mut total: u64 = files.iter().map(|(_, _, size)| *size).sum();
    for (path, _, size) in files {
        if total <= max_total_bytes {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
    Ok(())
}

fn collect_pcaps(
    directory: &Path, files: &mut Vec<(PathBuf, SystemTime, u64)>,
) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_pcaps(&path, files)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("pcap") {
            if let Ok(metadata) = entry.metadata() {
                files.push((
                    path,
                    metadata.modified().unwrap_or(UNIX_EPOCH),
                    metadata.len(),
                ));
            }
        }
    }
    Ok(())
}
