//! Cross-platform device fingerprinting and OS/hardware metadata for tunnel
//! audit trails and single-device-per-tunnel enforcement.

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

/// HTTP header carrying the privacy-hashed machine fingerprint (`sg1_<16hex>`).
pub const HEADER_DEVICE_ID: &str = "x-streamgate-device-id";

/// HTTP header carrying URL-safe Base64 encoded UTF-8 device/OS key-value lines.
pub const HEADER_DEVICE_INFO: &str = "x-streamgate-device-info";

const DEVICE_HASH_DOMAIN: &str = "xujclab-streamgate-device-v1:";
const NET_FALLBACK_DOMAIN: &str = "xujclab-streamgate-net-v1:";
const MAX_INFO_DECODED_BYTES: usize = 768;
const MAX_FIELD_CHARS: usize = 96;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceMetadata {
    pub device_id: String,
    pub os: String,
    pub model: String,
    pub client: String,
    pub browser: String,
}

impl DeviceMetadata {
    /// Human-readable summary combining OS, hardware model, client version, and browser hint.
    pub fn summary(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(4);
        for item in [
            self.os.as_str(),
            self.model.as_str(),
            self.client.as_str(),
            self.browser.as_str(),
        ] {
            let trimmed = item.trim();
            if !trimmed.is_empty() && !parts.contains(&trimmed) {
                parts.push(trimmed);
            }
        }
        if parts.is_empty() {
            "未知设备（旧版客户端或直连脚本）".to_string()
        } else {
            parts.join(" · ")
        }
    }

    /// ASCII-only `User-Agent` value safe for all HTTP proxies.
    pub fn ascii_user_agent(&self) -> String {
        let client_part = sanitize_ascii_header(if self.client.is_empty() {
            "LabStreamGate"
        } else {
            &self.client
        });
        let os_part = sanitize_ascii_header(&self.os);
        if os_part.is_empty() {
            client_part
        } else {
            format!("{client_part} ({os_part})")
        }
    }

    /// Encodes UTF-8 fields as URL-safe Base64 (no padding) for `X-StreamGate-Device-Info`.
    pub fn encode_info_header(&self) -> String {
        let payload = format!(
            "v1\nos={}\nmodel={}\nclient={}\nbrowser={}",
            sanitize_field(&self.os),
            sanitize_field(&self.model),
            sanitize_field(&self.client),
            sanitize_field(&self.browser),
        );
        base64url_encode(payload.as_bytes())
    }
}

static HOST_OS_OVERRIDE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static CACHED_BASE_DEVICE: OnceLock<(String, String, String)> = OnceLock::new();

/// Allows the desktop daemon (which already links `sysinfo`) to supply an in-process
/// OS version string before tunnels are opened.
pub fn set_host_os_override(os_description: String) {
    let sanitized = sanitize_field(&os_description);
    if sanitized.is_empty() {
        return;
    }
    let lock = HOST_OS_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = Some(sanitized);
    }
}

/// Returns the cached local machine fingerprint and OS/model profile.
pub fn local_device_profile(client_label: &str, browser_hint: Option<&str>) -> DeviceMetadata {
    let (device_id, detected_os, model) = CACHED_BASE_DEVICE
        .get_or_init(|| {
            let seed = resolve_machine_seed();
            let digest = sha256_hex(format!("{DEVICE_HASH_DOMAIN}{seed}").as_bytes());
            let device_id = format!("sg1_{}", &digest[..16]);
            let os = detect_os_description();
            let model = detect_hardware_model();
            (device_id, os, model)
        })
        .clone();

    let os = HOST_OS_OVERRIDE
        .get()
        .and_then(|m| m.lock().ok().and_then(|g| g.clone()))
        .unwrap_or(detected_os);

    DeviceMetadata {
        device_id,
        os,
        model,
        client: sanitize_field(client_label),
        browser: browser_hint.map(sanitize_field).unwrap_or_default(),
    }
}

/// Builds a WebSocket client handshake request populated with device identity headers.
#[cfg(feature = "client")]
pub fn build_ws_client_request(
    url: &str, client_label: &str, browser_hint: Option<&str>,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::client::Request,
    tokio_tungstenite::tungstenite::Error,
> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

    let mut request = url.into_client_request()?;
    let profile = local_device_profile(client_label, browser_hint);
    let headers = request.headers_mut();

    if let Ok(ua) = HeaderValue::from_str(&profile.ascii_user_agent()) {
        headers.insert("user-agent", ua);
    }
    if let Ok(id_val) = HeaderValue::from_str(&profile.device_id) {
        headers.insert(HEADER_DEVICE_ID, id_val);
    }
    if let Ok(info_val) = HeaderValue::from_str(&profile.encode_info_header()) {
        headers.insert(HEADER_DEVICE_INFO, info_val);
    }
    Ok(request)
}

/// Parses incoming WebSocket upgrade headers on the server into normalized `DeviceMetadata`.
pub fn parse_incoming_device(
    device_id_hdr: Option<&str>, device_info_hdr: Option<&str>, user_agent_hdr: Option<&str>,
    accept_lang_hdr: Option<&str>, client_ip: IpAddr,
) -> DeviceMetadata {
    let mut meta = DeviceMetadata::default();

    if let Some(raw_info) = device_info_hdr
        && raw_info.len() <= MAX_INFO_DECODED_BYTES * 2
        && let Some(decoded) = base64url_decode(raw_info.trim())
        && decoded.len() <= MAX_INFO_DECODED_BYTES
        && let Ok(text) = std::str::from_utf8(&decoded)
    {
        let mut lines = text.lines();
        if lines.next() == Some("v1") {
            for line in lines {
                if let Some((k, v)) = line.split_once('=') {
                    let clean = sanitize_field(v);
                    match k {
                        "os" => meta.os = clean,
                        "model" => meta.model = clean,
                        "client" => meta.client = clean,
                        "browser" => meta.browser = clean,
                        _ => {}
                    }
                }
            }
        }
    }

    let ua = user_agent_hdr.map(sanitize_field).unwrap_or_default();
    if meta.os.is_empty() && !ua.is_empty() {
        let (parsed_os, parsed_client) = infer_from_user_agent(&ua);
        meta.os = parsed_os;
        if meta.client.is_empty() {
            meta.client = parsed_client;
        }
    } else if meta.client.is_empty() && !ua.is_empty() {
        meta.client = ua.chars().take(64).collect();
    }

    if let Some(id) = device_id_hdr.map(str::trim)
        && is_valid_client_device_id(id)
    {
        meta.device_id = id.to_ascii_lowercase();
    } else {
        let lang = accept_lang_hdr.map(sanitize_field).unwrap_or_default();
        let fallback_input = format!("{NET_FALLBACK_DOMAIN}{client_ip}|{ua}|{lang}");
        let digest = sha256_hex(fallback_input.as_bytes());
        meta.device_id = format!("net_{}", &digest[..16]);
    }

    meta
}

pub fn is_valid_client_device_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sg1_") else {
        return false;
    };
    (16..=64).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn infer_from_user_agent(ua: &str) -> (String, String) {
    let lower = ua.to_ascii_lowercase();
    let os = if lower.contains("mac os x") || lower.contains("macos") || lower.contains("darwin") {
        "macOS".to_string()
    } else if lower.contains("windows nt 10.0") || lower.contains("windows 11") {
        "Windows 10/11".to_string()
    } else if lower.contains("windows") {
        "Windows".to_string()
    } else if lower.contains("android") {
        "Android".to_string()
    } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ios") {
        "iOS".to_string()
    } else if lower.contains("linux") {
        "Linux".to_string()
    } else {
        String::new()
    };

    let client = if lower.starts_with("labstreamgate") {
        ua.split('(').next().unwrap_or(ua).trim().to_string()
    } else if lower.contains("python") {
        "Python WebSocket".to_string()
    } else if lower.contains("curl/") {
        "curl".to_string()
    } else if lower.contains("go-http-client") {
        "Go HTTP Client".to_string()
    } else {
        ua.chars().take(48).collect()
    };
    (os, client)
}

fn sanitize_field(value: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_control() {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        out.push(ch);
        if out.chars().count() >= MAX_FIELD_CHARS {
            break;
        }
    }
    out.trim().to_string()
}

fn sanitize_ascii_header(value: &str) -> String {
    value
        .chars()
        .filter(|&ch| ch.is_ascii() && (0x20..=0x7E).contains(&(ch as u8)))
        .take(80)
        .collect::<String>()
        .trim()
        .to_string()
}

fn resolve_machine_seed() -> String {
    if let Some(hw) = platform_hardware_uuid() {
        let trimmed = hw.trim();
        if trimmed.len() >= 8 {
            return format!("hw:{trimmed}");
        }
    }
    load_or_create_persistent_seed()
}

fn load_or_create_persistent_seed() -> String {
    let path = device_seed_file_path();
    if let Some(ref p) = path
        && let Ok(existing) = std::fs::read_to_string(p)
    {
        let trimmed = existing.trim();
        if trimmed.len() >= 16 {
            return format!("seed:{trimmed}");
        }
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    let generated = sha256_hex(
        format!(
            "generated:{nanos}:{pid}:{host}:{}:{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .as_bytes(),
    );

    if let Some(p) = path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&p, &generated);
    }
    format!("seed:{generated}")
}

fn device_seed_file_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("com.xujclab.streamgate")
                .join("device_seed")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(|dir| {
                PathBuf::from(dir)
                    .join("xujclab")
                    .join("streamgate")
                    .join("device_seed")
            })
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return Some(PathBuf::from(xdg).join("streamgate").join("device_seed"));
        }
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("streamgate")
                .join("device_seed")
        })
    }
}

#[cfg(target_os = "macos")]
fn platform_hardware_uuid() -> Option<String> {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains("IOPlatformUUID")
            && let Some((_, rhs)) = line.split_once('=')
        {
            let cleaned = rhs.trim().trim_matches('"').trim();
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn platform_hardware_uuid() -> Option<String> {
    query_windows_reg_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_hardware_uuid() -> Option<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let trimmed = content.trim();
            if trimmed.len() >= 16 {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn detect_os_description() -> String {
    let arch = std::env::consts::ARCH;
    #[cfg(target_os = "macos")]
    {
        if let Ok(plist) =
            std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
        {
            let name =
                extract_plist_string(&plist, "ProductName").unwrap_or_else(|| "macOS".to_string());
            if let Some(ver) = extract_plist_string(&plist, "ProductVersion") {
                return format!("{name} {ver} ({arch})");
            }
        }
        format!("macOS ({arch})")
    }
    #[cfg(target_os = "windows")]
    {
        let product = query_windows_reg_value(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .unwrap_or_else(|| "Windows".to_string());
        let build = query_windows_reg_value(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuildNumber",
        )
        .unwrap_or_default();
        let build_num = build.parse::<u32>().unwrap_or(0);
        let normalized_product = if build_num >= 22000 && product.contains("Windows 10") {
            product.replacen("Windows 10", "Windows 11", 1)
        } else {
            product
        };
        if build.is_empty() {
            format!("{normalized_product} ({arch})")
        } else {
            format!("{normalized_product} Build {build} ({arch})")
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
            for line in os_release.lines() {
                if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                    let clean = val.trim().trim_matches('"').trim();
                    if !clean.is_empty() {
                        return format!("{clean} ({arch})");
                    }
                }
            }
        }
        format!("{} ({arch})", std::env::consts::OS)
    }
}

fn detect_hardware_model() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sysctl")
            .args(["-n", "hw.model"])
            .output()
        {
            let model = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !model.is_empty() {
                return model;
            }
        }
        "Apple Mac".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        let vendor = query_windows_reg_value(
            r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
            "SystemManufacturer",
        )
        .unwrap_or_default();
        let product = query_windows_reg_value(
            r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
            "SystemProductName",
        )
        .unwrap_or_default();
        combine_vendor_product(&vendor, &product)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let vendor =
            std::fs::read_to_string("/sys/devices/virtual/dmi/id/sys_vendor").unwrap_or_default();
        let product =
            std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name").unwrap_or_default();
        let combined = combine_vendor_product(&vendor, &product);
        if !combined.is_empty() {
            return combined;
        }
        if std::path::Path::new("/.dockerenv").exists() {
            return "Container".to_string();
        }
        String::new()
    }
}

#[cfg(not(target_os = "macos"))]
fn combine_vendor_product(vendor_raw: &str, product_raw: &str) -> String {
    let clean_part = |s: &str| -> String {
        let trimmed = sanitize_field(s);
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty()
            || lower.contains("to be filled")
            || lower.contains("default string")
            || lower == "system manufacturer"
            || lower == "system product name"
            || lower == "unknown"
            || lower == "none"
        {
            String::new()
        } else {
            trimmed
        }
    };
    let vendor = clean_part(vendor_raw);
    let product = clean_part(product_raw);
    if vendor.is_empty() {
        product
    } else if product.is_empty()
        || product
            .to_ascii_lowercase()
            .starts_with(&vendor.to_ascii_lowercase())
    {
        if product.is_empty() { vendor } else { product }
    } else {
        format!("{vendor} {product}")
    }
}

#[cfg(target_os = "macos")]
fn extract_plist_string(plist: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let idx = plist.find(&needle)?;
    let rest = &plist[idx + needle.len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    let val = rest[start..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

#[cfg(target_os = "windows")]
fn query_windows_reg_value(key_path: &str, value_name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let output = std::process::Command::new("reg")
        .args(["query", key_path, "/v", value_name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(value_name)
            && let Some(idx) = trimmed.find("REG_")
        {
            let after_type = &trimmed[idx..];
            if let Some(space_idx) = after_type.find(char::is_whitespace) {
                let val = after_type[space_idx..].trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// ── Self-contained SHA-256 (FIPS 180-4) & RFC 4648 Base64URL ──────────────

const SHA256_K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (&k, &wi) in SHA256_K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for word in state {
        for byte in word.to_be_bytes() {
            hex.push(HEX[(byte >> 4) as usize] as char);
            hex.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    hex
}

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

pub fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let decode_char = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None,
        }
    };
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = decode_char(bytes[i])?;
        let b = decode_char(bytes[i + 1])?;
        let c = decode_char(bytes[i + 2])?;
        let d = decode_char(bytes[i + 3])?;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
        out.push((n & 0xFF) as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let a = decode_char(bytes[i])?;
        let b = decode_char(bytes[i + 1])?;
        let n = (a << 18) | (b << 12);
        out.push(((n >> 16) & 0xFF) as u8);
    } else if rem == 3 {
        let a = decode_char(bytes[i])?;
        let b = decode_char(bytes[i + 1])?;
        let c = decode_char(bytes[i + 2])?;
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn device_info_header_round_trips_utf8_models() {
        let original = DeviceMetadata {
            device_id: "sg1_0123456789abcdef".into(),
            os: "Windows 11 Pro Build 26100 (x86_64)".into(),
            model: "华为 MateBook X Pro".into(),
            client: "Desktop 0.6.10".into(),
            browser: "Chrome 134".into(),
        };
        let encoded = original.encode_info_header();
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );

        let parsed = parse_incoming_device(
            Some(&original.device_id),
            Some(&encoded),
            Some(&original.ascii_user_agent()),
            None,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        );
        assert_eq!(parsed, original);
        assert_eq!(
            parsed.summary(),
            "Windows 11 Pro Build 26100 (x86_64) · 华为 MateBook X Pro · Desktop 0.6.10 · Chrome 134"
        );
    }

    #[test]
    fn fallback_fingerprint_distinguishes_legacy_clients() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));
        let dev1 = parse_incoming_device(None, None, Some("Python/3.12 websockets"), None, ip1);
        let dev2 = parse_incoming_device(None, None, Some("Python/3.12 websockets"), None, ip2);
        assert!(dev1.device_id.starts_with("net_"));
        assert_ne!(dev1.device_id, dev2.device_id);
        assert_eq!(dev1.client, "Python WebSocket");
    }
}
