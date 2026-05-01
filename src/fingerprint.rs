use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Default)]
pub struct ServiceFingerprint {
    pub service: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub raw_banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OsHint {
    pub guess: String,
    pub ttl: Option<u8>,
    pub confidence: &'static str,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DeepFindings {
    pub os_hint: Option<OsHint>,
    pub vulns: Vec<VulnNote>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnNote {
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
}

static SSH_RE: OnceLock<Regex> = OnceLock::new();
static HTTP_SERVER_RE: OnceLock<Regex> = OnceLock::new();
static HTTP_STATUS_RE: OnceLock<Regex> = OnceLock::new();
static FTP_RE: OnceLock<Regex> = OnceLock::new();
static SMTP_RE: OnceLock<Regex> = OnceLock::new();
static POP3_RE: OnceLock<Regex> = OnceLock::new();
static IMAP_RE: OnceLock<Regex> = OnceLock::new();
static REDIS_RE: OnceLock<Regex> = OnceLock::new();
static MYSQL_RE: OnceLock<Regex> = OnceLock::new();
static POSTGRES_RE: OnceLock<Regex> = OnceLock::new();
static MONGODB_RE: OnceLock<Regex> = OnceLock::new();
static VNC_RE: OnceLock<Regex> = OnceLock::new();

fn ssh_re() -> &'static Regex {
    SSH_RE.get_or_init(|| Regex::new(r"SSH-(\d+\.\d+)-(\S+)").unwrap())
}
fn http_server_re() -> &'static Regex {
    HTTP_SERVER_RE.get_or_init(|| Regex::new(r"(?i)^Server:\s*(.+)$").unwrap())
}
fn http_status_re() -> &'static Regex {
    HTTP_STATUS_RE.get_or_init(|| Regex::new(r"HTTP/[\d.]+ (\d{3})").unwrap())
}
fn ftp_re() -> &'static Regex {
    FTP_RE.get_or_init(|| Regex::new(r"220[- ](.+)").unwrap())
}
fn smtp_re() -> &'static Regex {
    SMTP_RE.get_or_init(|| Regex::new(r"220[- ](\S+)\s+(.+)").unwrap())
}
fn pop3_re() -> &'static Regex {
    POP3_RE.get_or_init(|| Regex::new(r"\+OK\s+(.+)").unwrap())
}
fn imap_re() -> &'static Regex {
    IMAP_RE.get_or_init(|| Regex::new(r"\* OK\s+(.+)").unwrap())
}
fn redis_re() -> &'static Regex {
    REDIS_RE.get_or_init(|| Regex::new(r"redis_version:(\S+)").unwrap())
}
fn mysql_re() -> &'static Regex {
    MYSQL_RE.get_or_init(|| Regex::new(r"(\d+\.\d+\.\d+)[- ].*MySQL").unwrap())
}
fn postgres_re() -> &'static Regex {
    POSTGRES_RE.get_or_init(|| Regex::new(r"PostgreSQL (\S+)").unwrap())
}
fn mongodb_re() -> &'static Regex {
    MONGODB_RE.get_or_init(|| Regex::new(r"MongoDB").unwrap())
}
fn vnc_re() -> &'static Regex {
    VNC_RE.get_or_init(|| Regex::new(r"RFB (\d+\.\d+)").unwrap())
}

pub async fn grab_banner(addr: std::net::SocketAddr, timeout: Duration) -> Option<String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let _ = stream.write_all(b"\r\n").await;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

async fn probe_http(addr: std::net::SocketAddr, timeout: Duration) -> Option<String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: hatmap/0.1\r\nConnection: close\r\n\r\n",
        addr.ip()
    );
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn probe_redis(addr: std::net::SocketAddr, timeout: Duration) -> Option<String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(timeout, stream.write_all(b"INFO server\r\n"))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn probe_ftp(addr: std::net::SocketAddr, timeout: Duration) -> Option<String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();

    tokio::time::timeout(timeout, stream.write_all(b"USER anonymous\r\n"))
        .await
        .ok()?
        .ok()?;

    let mut buf2 = vec![0u8; 256];
    let n2 = tokio::time::timeout(timeout, stream.read(&mut buf2))
        .await
        .ok()?
        .ok()?;

    let auth_resp = if n2 > 0 {
        String::from_utf8_lossy(&buf2[..n2]).to_string()
    } else {
        String::new()
    };

    Some(format!("{}\n{}", banner.trim(), auth_resp.trim()))
}

#[cfg_attr(not(feature = "raw-syn"), allow(dead_code))]
pub fn os_hint_from_ttl(ttl: u8) -> OsHint {
    let (guess, confidence) = match ttl {
        64 => ("Linux / macOS / BSD", "medium"),
        128 => ("Windows", "medium"),
        255 => ("Cisco IOS / Solaris", "medium"),
        63 | 65..=70 => ("Linux (behind 1 hop)", "low"),
        127 | 129..=135 => ("Windows (behind 1 hop)", "low"),
        _ => ("Unknown", "very-low"),
    };
    OsHint {
        guess: guess.to_string(),
        ttl: Some(ttl),
        confidence,
    }
}

pub fn identify(port: u16, banner: Option<String>) -> ServiceFingerprint {
    let raw_banner = banner.and_then(|s| if s.is_empty() { None } else { Some(s) });
    let lower = raw_banner.as_deref().unwrap_or_default().to_ascii_lowercase();

    if let Some(cap) = raw_banner.as_deref().and_then(|b| ssh_re().captures(b)) {
        return ServiceFingerprint {
            service: "ssh".to_string(),
            version: cap.get(1).map(|m| m.as_str().to_string()),
            product: cap.get(2).map(|m| m.as_str().to_string()),
            raw_banner,
        };
    }

    if lower.contains("redis") || lower.starts_with('*') || lower.starts_with('$') || lower.starts_with('-') {
        let version = redis_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        return ServiceFingerprint {
            service: "redis".to_string(),
            version,
            product: Some("Redis".to_string()),
            raw_banner,
        };
    }

    if lower.contains("220") && (lower.contains("ftp") || port == 21) {
        let product = ftp_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());
        return ServiceFingerprint {
            service: "ftp".to_string(),
            version: None,
            product,
            raw_banner,
        };
    }

    if lower.contains("220") && lower.contains("smtp") {
        let product = smtp_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(2))
            .map(|m| m.as_str().trim().to_string());
        return ServiceFingerprint {
            service: "smtp".to_string(),
            version: None,
            product,
            raw_banner,
        };
    }

    if lower.starts_with("+ok") || (port == 110 && lower.contains("+ok")) {
        let product = pop3_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());
        return ServiceFingerprint {
            service: "pop3".to_string(),
            version: None,
            product,
            raw_banner,
        };
    }

    if lower.starts_with("* ok") || (port == 143 && lower.contains("* ok")) {
        let product = imap_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());
        return ServiceFingerprint {
            service: "imap".to_string(),
            version: None,
            product,
            raw_banner,
        };
    }

    if lower.contains("http/") || lower.contains("server:") {
        let server_line = raw_banner.as_deref().and_then(|b| {
            b.lines().find_map(|l| {
                http_server_re()
                    .captures(l)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
            })
        });
        return ServiceFingerprint {
            service: "http".to_string(),
            version: None,
            product: server_line,
            raw_banner,
        };
    }

    if lower.contains("mysql") || (port == 3306 && !lower.is_empty()) {
        let version = mysql_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        return ServiceFingerprint {
            service: "mysql".to_string(),
            version,
            product: Some("MySQL".to_string()),
            raw_banner,
        };
    }

    if lower.contains("postgresql") {
        let version = postgres_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        return ServiceFingerprint {
            service: "postgresql".to_string(),
            version,
            product: Some("PostgreSQL".to_string()),
            raw_banner,
        };
    }

    if lower.contains("mongodb") {
        let _ = mongodb_re();
        return ServiceFingerprint {
            service: "mongodb".to_string(),
            version: None,
            product: Some("MongoDB".to_string()),
            raw_banner,
        };
    }

    if vnc_re().is_match(raw_banner.as_deref().unwrap_or_default()) {
        let version = vnc_re()
            .captures(raw_banner.as_deref().unwrap_or_default())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        return ServiceFingerprint {
            service: "vnc".to_string(),
            version,
            product: Some("VNC".to_string()),
            raw_banner,
        };
    }

    ServiceFingerprint {
        service: well_known_service(port).to_string(),
        version: None,
        product: None,
        raw_banner,
    }
}

pub async fn deep_probe(
    addr: std::net::SocketAddr,
    port: u16,
    fingerprint: &ServiceFingerprint,
    timeout: Duration,
) -> DeepFindings {
    let mut vulns: Vec<VulnNote> = Vec::new();

    match fingerprint.service.as_str() {
        "http" | "https" => {
            if let Some(body) = probe_http(addr, timeout).await {
                check_http_vulns(&body, &mut vulns);
            }
        }
        "redis" => {
            check_redis_vulns(addr, timeout, &mut vulns).await;
        }
        "ftp" => {
            if let Some(combined) = probe_ftp(addr, timeout).await {
                check_ftp_vulns(&combined, &mut vulns);
            }
        }
        _ => {}
    }

    check_generic_port_vulns(port, fingerprint, &mut vulns);

    DeepFindings { os_hint: None, vulns }
}

fn check_http_vulns(response: &str, vulns: &mut Vec<VulnNote>) {
    let lower = response.to_ascii_lowercase();

    let expose_headers = ["x-powered-by:", "x-aspnet-version:", "x-aspnetmvc-version:"];
    for hdr in expose_headers {
        if lower.contains(hdr) {
            let value = response
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with(hdr))
                .unwrap_or("")
                .trim()
                .to_string();
            vulns.push(VulnNote {
                severity: "INFO",
                title: "Technology Disclosure".to_string(),
                detail: format!("Header reveals stack: {}", value),
            });
        }
    }

    if let Some(cap) = http_server_re()
        .captures(response.lines().find(|l| l.to_ascii_lowercase().starts_with("server:")).unwrap_or(""))
    {
        let sv = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        if !sv.is_empty() {
            vulns.push(VulnNote {
                severity: "INFO",
                title: "Server Version Disclosure".to_string(),
                detail: format!("Server: {}", sv),
            });
        }
    }

    if !lower.contains("x-frame-options:") {
        vulns.push(VulnNote {
            severity: "LOW",
            title: "Missing X-Frame-Options".to_string(),
            detail: "Response lacks X-Frame-Options header (clickjacking risk)".to_string(),
        });
    }

    if !lower.contains("x-content-type-options:") {
        vulns.push(VulnNote {
            severity: "LOW",
            title: "Missing X-Content-Type-Options".to_string(),
            detail: "Response lacks X-Content-Type-Options: nosniff".to_string(),
        });
    }

    if !lower.contains("strict-transport-security:") && lower.contains("https") {
        vulns.push(VulnNote {
            severity: "MEDIUM",
            title: "Missing HSTS".to_string(),
            detail: "HTTPS service does not set Strict-Transport-Security".to_string(),
        });
    }

    if lower.contains("<title>index of") || lower.contains("directory listing") {
        vulns.push(VulnNote {
            severity: "MEDIUM",
            title: "Directory Listing Enabled".to_string(),
            detail: "Web server is serving a directory index page".to_string(),
        });
    }

    if http_status_re()
        .captures(response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str() == "200")
        .unwrap_or(false)
        && lower.contains("robots.txt")
    {
        vulns.push(VulnNote {
            severity: "INFO",
            title: "robots.txt Present".to_string(),
            detail: "robots.txt may expose hidden paths".to_string(),
        });
    }
}

async fn check_redis_vulns(addr: std::net::SocketAddr, timeout: Duration, vulns: &mut Vec<VulnNote>) {
    if let Some(info) = probe_redis(addr, timeout).await {
        if !info.starts_with("-NOAUTH") && !info.starts_with("-ERR") {
            vulns.push(VulnNote {
                severity: "CRITICAL",
                title: "Redis No Authentication".to_string(),
                detail: "Redis instance accepts commands without authentication — full data access possible".to_string(),
            });
            if info.to_ascii_lowercase().contains("redis_version:") {
                let version = redis_re()
                    .captures(&info)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                vulns.push(VulnNote {
                    severity: "INFO",
                    title: "Redis Version".to_string(),
                    detail: format!("Detected version: {}", version),
                });
            }
        }
    }
}

fn check_ftp_vulns(combined: &str, vulns: &mut Vec<VulnNote>) {
    let lower = combined.to_ascii_lowercase();
    if lower.contains("331") || lower.contains("230") || lower.contains("anonymous") {
        vulns.push(VulnNote {
            severity: "HIGH",
            title: "Anonymous FTP Login".to_string(),
            detail: "FTP server accepted 'anonymous' user — unauthenticated access possible".to_string(),
        });
    }
    if lower.contains("vsftpd") {
        if lower.contains("vsftpd 2.3.4") {
            vulns.push(VulnNote {
                severity: "CRITICAL",
                title: "vsftpd 2.3.4 Backdoor".to_string(),
                detail: "CVE-2011-2523: vsftpd 2.3.4 contains a backdoor triggered by ':)' in username".to_string(),
            });
        }
    }
}

fn check_generic_port_vulns(port: u16, fp: &ServiceFingerprint, vulns: &mut Vec<VulnNote>) {
    match port {
        23 => vulns.push(VulnNote {
            severity: "HIGH",
            title: "Telnet Detected".to_string(),
            detail: "Telnet transmits credentials in plaintext".to_string(),
        }),
        512 | 513 | 514 => vulns.push(VulnNote {
            severity: "HIGH",
            title: "r-Services Detected".to_string(),
            detail: format!("Port {} (rexec/rlogin/rsh) — legacy, unauthenticated remote access", port),
        }),
        2181 => vulns.push(VulnNote {
            severity: "MEDIUM",
            title: "ZooKeeper Exposed".to_string(),
            detail: "ZooKeeper typically has no authentication by default".to_string(),
        }),
        9200 | 9300 => vulns.push(VulnNote {
            severity: "HIGH",
            title: "Elasticsearch Exposed".to_string(),
            detail: "Elasticsearch REST API may be unauthenticated — full data access possible".to_string(),
        }),
        27017 | 27018 => vulns.push(VulnNote {
            severity: "HIGH",
            title: "MongoDB Exposed".to_string(),
            detail: "MongoDB may accept connections without authentication".to_string(),
        }),
        5900..=5910 => vulns.push(VulnNote {
            severity: "MEDIUM",
            title: "VNC Exposed".to_string(),
            detail: format!("VNC on port {} — check authentication strength", port),
        }),
        _ => {}
    }

    if let Some(v) = &fp.version {
        if fp.service == "ssh" {
            let parts: Vec<&str> = v.split('.').collect();
            if parts.first().copied() == Some("1") {
                vulns.push(VulnNote {
                    severity: "HIGH",
                    title: "SSH Protocol v1".to_string(),
                    detail: "SSHv1 is deprecated and vulnerable to several attacks".to_string(),
                });
            }
        }
    }
}

fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 8080 | 8000 | 8008 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 | 4443 => "https",
        445 => "smb",
        512 => "rexec",
        513 => "rlogin",
        514 => "rsh",
        3306 => "mysql",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}
