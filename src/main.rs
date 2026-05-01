mod fingerprint;
#[cfg(feature = "raw-syn")]
mod packet;
mod scanner;
mod ui;

use anyhow::Result;
use clap::{ArgAction, Parser, ValueEnum};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use prettytable::{row, Table};
use scanner::{OutputFormat, ScanMode, ScannerConfig};
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::lookup_host;

#[derive(Debug, Parser)]
#[command(
    name = "nebula-scan",
    version,
    about = "High-performance async TCP scanner with deep inspection"
)]
struct Cli {
    #[arg(help = "CIDR range, IP address, or hostname")]
    target: String,

    #[arg(
        short,
        long,
        default_value = "1-1024",
        help = "Port list/ranges, e.g. 22,80,443 or 1-1024"
    )]
    ports: String,

    #[arg(
        short = 'c',
        long,
        default_value_t = 512,
        help = "Maximum in-flight scan tasks"
    )]
    concurrency: usize,

    #[arg(long, default_value_t = 800, help = "Initial timeout in milliseconds")]
    timeout_ms: u64,

    #[arg(long, value_enum, default_value_t = CliScanMode::Auto)]
    mode: CliScanMode,

    #[arg(long, action = ArgAction::SetTrue, help = "Shortcut for --mode syn")]
    syn: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "Shortcut for --mode connect")]
    connect: bool,

    #[arg(long, value_enum, default_value_t = CliOutputFormat::Pretty)]
    output: CliOutputFormat,

    #[arg(
        short = 'A',
        long = "deep",
        action = ArgAction::SetTrue,
        help = "Deep scan: service version detection + vuln analysis on each open port"
    )]
    deep: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum CliScanMode {
    Auto,
    Syn,
    Connect,
}

#[derive(Debug, Clone, ValueEnum)]
enum CliOutputFormat {
    Pretty,
    Json,
    Tui,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    anyhow::ensure!(
        !(cli.syn && cli.connect),
        "--syn and --connect cannot be used together"
    );

    let mode = if cli.syn {
        ScanMode::Syn
    } else if cli.connect {
        ScanMode::Connect
    } else {
        match cli.mode {
            CliScanMode::Auto => ScanMode::Auto,
            CliScanMode::Syn => ScanMode::Syn,
            CliScanMode::Connect => ScanMode::Connect,
        }
    };

    let config = ScannerConfig {
        targets: parse_targets(&cli.target).await?,
        ports: parse_ports(&cli.ports)?,
        concurrency: cli.concurrency.max(1),
        initial_timeout: Duration::from_millis(cli.timeout_ms),
        mode,
        output: match cli.output {
            CliOutputFormat::Pretty => OutputFormat::Pretty,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Tui => OutputFormat::Tui,
        },
        deep: cli.deep,
    };

    let output = config.output;

    print_banner(cli.deep);

    if matches!(output, OutputFormat::Tui) {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let stop = scanner::StopHandle::new();
        let scanner_task =
            tokio::spawn(scanner::run_with_events(config, event_tx, stop.clone()));
        ui::run_tui(event_rx, stop).await?;
        scanner_task.await??;
    } else {
        let results = scanner::run(config).await?;
        match output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&results)?),
            OutputFormat::Pretty => print_table(&results),
            OutputFormat::Tui => unreachable!(),
        }
    }

    Ok(())
}

async fn parse_targets(input: &str) -> Result<Vec<IpAddr>> {
    if input.contains('/') {
        let network: ipnetwork::IpNetwork = input.parse()?;
        Ok(network.iter().collect())
    } else if let Ok(ip) = input.parse() {
        Ok(vec![ip])
    } else {
        let mut addrs = lookup_host((input, 0))
            .await?
            .map(|addr| addr.ip())
            .collect::<Vec<_>>();
        addrs.sort_unstable();
        addrs.dedup();
        anyhow::ensure!(
            !addrs.is_empty(),
            "hostname resolved to no addresses: {input}"
        );
        Ok(addrs)
    }
}

fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for chunk in input.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((start, end)) = chunk.split_once('-') {
            let start: u16 = start.trim().parse()?;
            let end: u16 = end.trim().parse()?;
            anyhow::ensure!(start <= end, "invalid port range: {chunk}");
            ports.extend(start..=end);
        } else {
            ports.push(chunk.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    anyhow::ensure!(!ports.is_empty(), "at least one port is required");
    Ok(ports)
}

fn print_banner(deep: bool) {
    // Doom-font HATMAP — each row is exactly 78 chars, verified clean at 80-col terminals
    const LOGO: [&str; 6] = [
        r" _   _   ___  _____ __  __  ___  ____  ",
        r"| | | | / _ \|_   _|  \/  |/ _ \|  _ \ ",
        r"| |_| |/ /_\ \ | | | |\/| / /_\ \ |_) |",
        r"|  _  ||  _  | | | | |  | |  _  |  __/ ",
        r"|_| |_||_| |_| |_| |_|  |_|_| |_|_|    ",
        r"                                         ",
    ];

    // Colours used throughout
    const C_LOGO_HI:  Color = Color::Rgb { r: 0,   g: 240, b: 255 }; // electric cyan
    const C_LOGO_LO:  Color = Color::Rgb { r: 0,   g: 180, b: 210 }; // mid teal
    const C_RULE:     Color = Color::Rgb { r: 0,   g: 120, b: 150 }; // dim teal
    const C_CREDIT:   Color = Color::Rgb { r: 255, g: 255, b: 255 }; // white
    const C_LABEL:    Color = Color::Rgb { r: 100, g: 100, b: 120 }; // dim grey
    const C_VALUE:    Color = Color::Rgb { r: 0,   g: 210, b: 140 }; // green
    const C_DEEP_VAL: Color = Color::Rgb { r: 255, g: 140, b:   0 }; // orange

    const RULE: &str =
        "  ──────────────────────────────────────────────────────";

    let mut out = io::stdout();

    // ── top padding ──────────────────────────────────────────
    let _ = execute!(out, Print("\n"));

    // ── logo rows: even = highlight, odd = mid ────────────────
    for (i, row) in LOGO.iter().enumerate() {
        let color = if i % 2 == 0 { C_LOGO_HI } else { C_LOGO_LO };
        let _ = execute!(out,
            SetForegroundColor(color),
            Print("  "),   // 2-space left margin
            Print(*row),
            Print("\n"),
        );
    }

    // ── top rule ──────────────────────────────────────────────
    let _ = execute!(out,
        SetForegroundColor(C_RULE),
        Print(RULE),
        Print("\n"),
    );

    // ── credit line ───────────────────────────────────────────
    let _ = execute!(out,
        SetForegroundColor(C_CREDIT),
        Print("  Developed by "),
        SetForegroundColor(C_LOGO_HI),
        Print("Elfaria Serfort"),
        Print("\n"),
    );

    // ── info rows — fixed 18-char label column ────────────────
    let mode_val   = if deep { "DEEP SCAN  (-A)" } else { "FAST SCAN" };
    let mode_color = if deep { C_DEEP_VAL } else { C_VALUE };

    let info: &[(&str, &str, Color)] = &[
        ("  Version         ", "v0.1.0",                            C_VALUE),
        ("  Tagline         ", "Fast & Safe Network Reconnaissance", C_VALUE),
    ];

    for (label, value, col) in info {
        let _ = execute!(out,
            SetForegroundColor(C_LABEL), Print(label),
            SetForegroundColor(*col),   Print(value),
            Print("\n"),
        );
    }

    let _ = execute!(out,
        SetForegroundColor(C_LABEL),    Print("  Mode             "),
        SetForegroundColor(mode_color), Print(mode_val),
        Print("\n"),
    );

    // ── bottom rule + padding ─────────────────────────────────
    let _ = execute!(out,
        SetForegroundColor(C_RULE),
        Print(RULE),
        Print("\n\n"),
    );

    let _ = execute!(out, ResetColor);
    let _ = out.flush();
}

fn print_table(results: &[scanner::ScanResult]) {
    let mut table = Table::new();
    let has_deep = results.iter().any(|r| r.deep.is_some());

    if has_deep {
        table.add_row(row![
            "Host", "Port", "State", "RTT ms", "Service", "Version", "Vulns"
        ]);
        for r in results {
            let vuln_summary = r.deep.as_ref().map(|d| {
                if d.vulns.is_empty() {
                    "-".to_string()
                } else {
                    let crit = d.vulns.iter().filter(|v| v.severity == "CRITICAL").count();
                    let high = d.vulns.iter().filter(|v| v.severity == "HIGH").count();
                    let med = d.vulns.iter().filter(|v| v.severity == "MEDIUM").count();
                    let low = d.vulns.iter().filter(|v| v.severity == "LOW").count();
                    let info = d.vulns.iter().filter(|v| v.severity == "INFO").count();
                    let mut parts = Vec::new();
                    if crit > 0 { parts.push(format!("{}✖CRIT", crit)); }
                    if high > 0 { parts.push(format!("{}✖HIGH", high)); }
                    if med > 0 { parts.push(format!("{}✖MED", med)); }
                    if low > 0 { parts.push(format!("{}✖LOW", low)); }
                    if info > 0 { parts.push(format!("{}✖INFO", info)); }
                    parts.join(" ")
                }
            }).unwrap_or_else(|| "-".to_string());

            let version = r.fingerprint.version.as_deref()
                .or(r.fingerprint.product.as_deref())
                .unwrap_or("-");

            table.add_row(row![
                r.host,
                r.port,
                r.state,
                r.rtt_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                r.fingerprint.service,
                version,
                vuln_summary
            ]);
        }
    } else {
        table.add_row(row![
            "Host", "Port", "State", "RTT ms", "Service", "Product"
        ]);
        for r in results {
            table.add_row(row![
                r.host,
                r.port,
                r.state,
                r.rtt_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                r.fingerprint.service,
                r.fingerprint.product.as_deref().unwrap_or("-")
            ]);
        }
    }

    table.printstd();

    if has_deep {
        for r in results {
            if let Some(deep) = &r.deep {
                if deep.vulns.is_empty() {
                    continue;
                }
                println!("\n  {}:{} — {} finding(s)", r.host, r.port, deep.vulns.len());
                for v in &deep.vulns {
                    println!("    [{:8}] {} — {}", v.severity, v.title, v.detail);
                }
            }
        }
    }
}
