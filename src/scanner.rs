use crate::fingerprint::{deep_probe, grab_banner, identify, DeepFindings, ServiceFingerprint};
#[cfg(feature = "raw-syn")]
use crate::packet;
#[cfg(feature = "raw-syn")]
use anyhow::anyhow;
#[cfg(feature = "raw-syn")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "raw-syn")]
use dashmap::DashMap;
#[cfg(feature = "raw-syn")]
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
#[cfg(feature = "raw-syn")]
use pnet::packet::ip::IpNextHeaderProtocols;
#[cfg(feature = "raw-syn")]
use pnet::packet::ipv4::Ipv4Packet;
#[cfg(feature = "raw-syn")]
use pnet::packet::tcp::{TcpFlags, TcpPacket};
#[cfg(feature = "raw-syn")]
use pnet::packet::Packet;
use serde::Serialize;
#[cfg(feature = "raw-syn")]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, Semaphore};

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    Auto,
    Syn,
    Connect,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Pretty,
    Json,
    Tui,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub initial_timeout: Duration,
    pub mode: ScanMode,
    pub output: OutputFormat,
    pub deep: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub host: IpAddr,
    pub port: u16,
    pub state: String,
    pub rtt_ms: Option<u128>,
    pub fingerprint: ServiceFingerprint,
    pub deep: Option<DeepFindings>,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started { total: usize },
    ProbeFinished,
    OpenPort(ScanResult),
    Log(String),
    Finished { results: Vec<ScanResult> },
    Stopped,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct StopHandle {
    stop: Arc<AtomicBool>,
}

impl StopHandle {
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "raw-syn")]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ProbeKey {
    host: Ipv4Addr,
    port: u16,
    source_port: u16,
}

#[derive(Debug, Clone)]
struct ScanJob {
    host: IpAddr,
    port: u16,
}

#[cfg(feature = "raw-syn")]
#[derive(Debug, Clone)]
struct SynResponse {
    key: ProbeKey,
    open: bool,
    received_at: Instant,
}

pub async fn run(config: ScannerConfig) -> Result<Vec<ScanResult>> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let stop = StopHandle::new();
    let task = tokio::spawn(run_with_events(config, event_tx, stop));
    let mut results = Vec::new();

    while let Some(event) = event_rx.recv().await {
        match event {
            ScanEvent::OpenPort(result) => results.push(result),
            ScanEvent::Finished { results: final_results } => {
                results = final_results;
                break;
            }
            ScanEvent::Error(err) => return Err(anyhow::anyhow!(err)),
            _ => {}
        }
    }

    task.await??;
    results.sort_by_key(|r| (r.host, r.port));
    Ok(results)
}

pub async fn run_with_events(
    config: ScannerConfig,
    event_tx: UnboundedSender<ScanEvent>,
    stop: StopHandle,
) -> Result<()> {
    let total = config.targets.len().saturating_mul(config.ports.len());
    let _ = event_tx.send(ScanEvent::Started { total });

    let result = if matches!(config.mode, ScanMode::Syn | ScanMode::Auto) {
        match run_syn_scan_stream(config.clone(), event_tx.clone(), stop.clone()).await {
            Ok(results) => Ok(results),
            Err(err) if matches!(config.mode, ScanMode::Auto) => {
                let _ = event_tx.send(ScanEvent::Log(format!(
                    "SYN scan unavailable ({err}); falling back to TCP connect scan"
                )));
                run_connect_scan_stream(config, event_tx.clone(), stop.clone()).await
            }
            Err(err) => Err(err),
        }
    } else {
        run_connect_scan_stream(config, event_tx.clone(), stop.clone()).await
    };

    match result {
        Ok(results) if stop.is_stopped() => {
            let _ = event_tx.send(ScanEvent::Stopped);
            let _ = event_tx.send(ScanEvent::Finished { results });
            Ok(())
        }
        Ok(results) => {
            let _ = event_tx.send(ScanEvent::Finished { results });
            Ok(())
        }
        Err(err) => {
            let message = err.to_string();
            let _ = event_tx.send(ScanEvent::Error(message));
            Err(err)
        }
    }
}

async fn run_connect_scan_stream(
    config: ScannerConfig,
    event_tx: UnboundedSender<ScanEvent>,
    stop: StopHandle,
) -> Result<Vec<ScanResult>> {
    let (job_tx, mut job_rx) = mpsc::channel::<ScanJob>(config.concurrency * 2);
    let (result_tx, mut result_rx) = mpsc::channel::<ScanResult>(config.concurrency * 2);
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let timeout = Arc::new(AdaptiveTimeout::new(config.initial_timeout));
    let deep = config.deep;

    let producer_targets = config.targets.clone();
    let producer_ports = config.ports.clone();
    let producer_stop = stop.clone();
    tokio::spawn(async move {
        for host in producer_targets {
            if producer_stop.is_stopped() {
                return;
            }
            for port in &producer_ports {
                if producer_stop.is_stopped()
                    || job_tx
                        .send(ScanJob { host, port: *port })
                        .await
                        .is_err()
                {
                    return;
                }
            }
        }
    });

    while let Some(job) = job_rx.recv().await {
        if stop.is_stopped() {
            break;
        }
        let permit = semaphore.clone().acquire_owned().await?;
        let result_tx = result_tx.clone();
        let timeout = timeout.clone();
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = connect_probe(job, timeout, deep).await;
            let _ = event_tx.send(ScanEvent::ProbeFinished);
            if let Some(result) = result {
                let _ = event_tx.send(ScanEvent::OpenPort(result.clone()));
                let _ = result_tx.send(result).await;
            }
        });
    }
    drop(result_tx);

    let mut results = Vec::new();
    while let Some(result) = result_rx.recv().await {
        results.push(result);
    }
    results.sort_by_key(|r| (r.host, r.port));
    Ok(results)
}

async fn connect_probe(
    job: ScanJob,
    adaptive: Arc<AdaptiveTimeout>,
    deep: bool,
) -> Option<ScanResult> {
    let addr = SocketAddr::new(job.host, job.port);
    let start = Instant::now();
    let timeout = adaptive.current();

    let _stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let rtt = start.elapsed();
    adaptive.record(rtt);

    let probe_timeout = timeout.min(Duration::from_secs(3));

    let banner = grab_banner(addr, probe_timeout).await;
    let fingerprint = identify(job.port, banner);

    let deep_findings = if deep {
        let findings = tokio::select! {
            f = deep_probe(addr, job.port, &fingerprint, probe_timeout) => f,
            _ = tokio::time::sleep(probe_timeout) => Default::default(),
        };
        Some(findings)
    } else {
        None
    };

    Some(ScanResult {
        host: job.host,
        port: job.port,
        state: "open".to_string(),
        rtt_ms: Some(rtt.as_millis()),
        fingerprint,
        deep: deep_findings,
    })
}

#[cfg(not(feature = "raw-syn"))]
async fn run_syn_scan_stream(
    config: ScannerConfig,
    event_tx: UnboundedSender<ScanEvent>,
    stop: StopHandle,
) -> Result<Vec<ScanResult>> {
    let _ = event_tx.send(ScanEvent::Log(
        "raw SYN support was not compiled in; using TCP connect scan".to_string(),
    ));
    run_connect_scan_stream(config, event_tx, stop).await
}

#[cfg(feature = "raw-syn")]
async fn run_syn_scan_stream(
    config: ScannerConfig,
    event_tx: UnboundedSender<ScanEvent>,
    stop: StopHandle,
) -> Result<Vec<ScanResult>> {
    let interface = packet::default_interface()?;
    let source_ip = packet::interface_ipv4(&interface)?;
    let pending: Arc<DashMap<ProbeKey, Instant>> = Arc::new(DashMap::new());
    let (response_tx, mut response_rx) = mpsc::channel::<SynResponse>(config.concurrency * 4);
    let sniffer_interface = interface.clone();
    let sniffer_pending = pending.clone();
    let deep = config.deep;

    std::thread::Builder::new()
        .name("hatmap-sniffer".to_string())
        .spawn(move || sniff_responses(sniffer_interface, sniffer_pending, response_tx))
        .context("spawn sniffer thread")?;

    let (job_tx, mut job_rx) = mpsc::channel::<ScanJob>(config.concurrency * 2);
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let adaptive = Arc::new(AdaptiveTimeout::new(config.initial_timeout));
    let source_port = Arc::new(AtomicU64::new(40000));

    let producer_targets = config
        .targets
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4())
        .collect::<Vec<_>>();
    let producer_ports = config.ports.clone();
    let producer_stop = stop.clone();
    tokio::spawn(async move {
        for host in producer_targets {
            if producer_stop.is_stopped() {
                return;
            }
            for port in &producer_ports {
                if producer_stop.is_stopped()
                    || job_tx.send(ScanJob { host, port: *port }).await.is_err()
                {
                    return;
                }
            }
        }
    });

    let mut tx = packet::open_sender(&interface)?;
    let destination_mac = interface.mac.ok_or_else(|| {
        anyhow!("gateway MAC discovery is not implemented; use --mode connect")
    })?;

    while let Some(job) = job_rx.recv().await {
        if stop.is_stopped() {
            break;
        }
        let _permit = semaphore.clone().acquire_owned().await?;
        let IpAddr::V4(destination_ip) = job.host else {
            continue;
        };
        let sport = 40000 + (source_port.fetch_add(1, Ordering::Relaxed) as u16 % 20000);
        let key = ProbeKey {
            host: destination_ip,
            port: job.port,
            source_port: sport,
        };
        let spec = packet::SynPacketSpec {
            source_ip,
            destination_ip,
            source_port: sport,
            destination_port: job.port,
            sequence: sport as u32 * 4099,
        };
        let syn = packet::build_syn_packet(&spec)?;
        pending.insert(key, Instant::now());
        packet::send_ipv4_tcp_frame(tx.as_mut(), &interface, destination_mac, &syn)?;
        let _ = event_tx.send(ScanEvent::ProbeFinished);
    }

    let probe_timeout = adaptive.current();
    let deadline = Instant::now() + probe_timeout.saturating_mul(2);
    let mut results = Vec::new();

    while !stop.is_stopped() && (Instant::now() < deadline || !pending.is_empty()) {
        match tokio::time::timeout(Duration::from_millis(50), response_rx.recv()).await {
            Ok(Some(response)) if response.open => {
                if let Some((_, sent_at)) = pending.remove(&response.key) {
                    let rtt = response.received_at.saturating_duration_since(sent_at);
                    adaptive.record(rtt);
                    let addr = SocketAddr::new(IpAddr::V4(response.key.host), response.key.port);
                    let banner_timeout = adaptive.current().min(Duration::from_secs(2));
                    let banner = grab_banner(addr, banner_timeout).await;
                    let fingerprint = identify(response.key.port, banner);

                    let deep_findings = if deep {
                        let findings = tokio::select! {
                            f = deep_probe(addr, response.key.port, &fingerprint, banner_timeout) => f,
                            _ = tokio::time::sleep(banner_timeout) => Default::default(),
                        };
                        Some(findings)
                    } else {
                        None
                    };

                    let result = ScanResult {
                        host: IpAddr::V4(response.key.host),
                        port: response.key.port,
                        state: "open".to_string(),
                        rtt_ms: Some(rtt.as_millis()),
                        fingerprint,
                        deep: deep_findings,
                    };
                    let _ = event_tx.send(ScanEvent::OpenPort(result.clone()));
                    results.push(result);
                }
            }
            Ok(Some(response)) => {
                pending.remove(&response.key);
            }
            _ => {
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
    }

    results.sort_by_key(|r| (r.host, r.port));
    Ok(results)
}

#[cfg(feature = "raw-syn")]
fn sniff_responses(
    interface: pnet::datalink::NetworkInterface,
    pending: Arc<DashMap<ProbeKey, Instant>>,
    response_tx: mpsc::Sender<SynResponse>,
) {
    let Ok(pnet::datalink::Channel::Ethernet(_, mut rx)) =
        pnet::datalink::channel(&interface, Default::default())
    else {
        return;
    };

    loop {
        let Ok(frame) = rx.next() else { continue };
        let Some(ethernet) = EthernetPacket::new(frame) else {
            continue;
        };
        if ethernet.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) else {
            continue;
        };
        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }
        let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
            continue;
        };
        let key = ProbeKey {
            host: ipv4.get_source(),
            port: tcp.get_source(),
            source_port: tcp.get_destination(),
        };
        if !pending.contains_key(&key) {
            continue;
        }

        let flags = tcp.get_flags();
        let open = flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0;
        let closed = flags & TcpFlags::RST != 0;
        if open || closed {
            let _ = response_tx.blocking_send(SynResponse {
                key,
                open,
                received_at: Instant::now(),
            });
        }
    }
}

struct AdaptiveTimeout {
    millis: AtomicU64,
}

impl AdaptiveTimeout {
    fn new(initial: Duration) -> Self {
        Self {
            millis: AtomicU64::new(initial.as_millis().clamp(50, 30_000) as u64),
        }
    }

    fn current(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::Relaxed))
    }

    fn record(&self, rtt: Duration) {
        let observed = (rtt.as_millis() as u64).clamp(10, 10_000);
        let current = self.millis.load(Ordering::Relaxed);
        let next = ((current * 7) + (observed * 6).max(100)) / 8;
        self.millis.store(next.clamp(50, 30_000), Ordering::Relaxed);
    }
}
