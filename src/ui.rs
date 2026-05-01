use crate::scanner::{ScanEvent, ScanResult, StopHandle};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedReceiver;

const PRIMARY: Color = Color::Rgb(0, 255, 70);
const CYAN: Color = Color::Rgb(0, 220, 220);
const DIM_GREEN: Color = Color::Rgb(0, 160, 50);
const YELLOW: Color = Color::Rgb(255, 210, 0);
const RED: Color = Color::Rgb(220, 40, 40);
const ORANGE: Color = Color::Rgb(255, 140, 0);
const DARK_BG: Color = Color::Rgb(8, 12, 8);
const BORDER: Color = Color::Rgb(0, 100, 30);

struct AppState {
    logs: Vec<String>,
    results: Vec<ScanResult>,
    selected: usize,
    list_state: ListState,
    total_probes: usize,
    finished_probes: usize,
    open_ports: usize,
    started_at: Instant,
    scan_done: bool,
    stopped: bool,
    pps_samples: Vec<(Instant, usize)>,
    last_pps: f64,
    deep_mode: bool,
}

impl AppState {
    fn new(total: usize) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            logs: Vec::new(),
            results: Vec::new(),
            selected: 0,
            list_state,
            total_probes: total,
            finished_probes: 0,
            open_ports: 0,
            started_at: Instant::now(),
            scan_done: false,
            stopped: false,
            pps_samples: Vec::new(),
            last_pps: 0.0,
            deep_mode: false,
        }
    }

    fn push_log(&mut self, msg: String) {
        self.logs.push(msg);
        if self.logs.len() > 500 {
            self.logs.remove(0);
        }
    }

    fn probe_finished(&mut self) {
        self.finished_probes += 1;
        let now = Instant::now();
        self.pps_samples.push((now, self.finished_probes));
        let cutoff = now - Duration::from_secs(2);
        self.pps_samples.retain(|(t, _)| *t >= cutoff);
        if self.pps_samples.len() >= 2 {
            let first = &self.pps_samples[0];
            let last = self.pps_samples.last().unwrap();
            let elapsed = last.0.duration_since(first.0).as_secs_f64();
            if elapsed > 0.0 {
                self.last_pps = (last.1 - first.1) as f64 / elapsed;
            }
        }
    }

    fn open_port(&mut self, result: ScanResult) {
        if result.deep.is_some() {
            self.deep_mode = true;
        }
        let vuln_count = result
            .deep
            .as_ref()
            .map(|d| d.vulns.len())
            .unwrap_or(0);

        let log_line = if vuln_count > 0 {
            format!(
                "[OPEN] {}:{} ({}) [{} finding(s)]",
                result.host, result.port, result.fingerprint.service, vuln_count
            )
        } else {
            format!(
                "[OPEN] {}:{} ({}) {}",
                result.host,
                result.port,
                result.fingerprint.service,
                result.fingerprint.product.as_deref().unwrap_or("")
            )
        };
        self.push_log(log_line);
        self.open_ports += 1;
        self.results.push(result);
        self.results.sort_by_key(|r| (r.host, r.port));
        if self.selected >= self.results.len() {
            self.selected = self.results.len().saturating_sub(1);
        }
        self.list_state.select(Some(self.selected));
    }

    fn eta_secs(&self) -> Option<u64> {
        if self.scan_done || self.total_probes == 0 || self.finished_probes == 0 {
            return None;
        }
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let rate = self.finished_probes as f64 / elapsed;
        if rate < 0.01 {
            return None;
        }
        Some(((self.total_probes - self.finished_probes) as f64 / rate) as u64)
    }

    fn progress_ratio(&self) -> f64 {
        if self.total_probes == 0 {
            return 1.0;
        }
        (self.finished_probes as f64 / self.total_probes as f64).clamp(0.0, 1.0)
    }

    fn select_up(&mut self) {
        if self.results.is_empty() {
            return;
        }
        self.selected = self.selected.saturating_sub(1);
        self.list_state.select(Some(self.selected));
    }

    fn select_down(&mut self) {
        if self.results.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.results.len() - 1);
        self.list_state.select(Some(self.selected));
    }

    fn total_vulns(&self) -> usize {
        self.results
            .iter()
            .filter_map(|r| r.deep.as_ref())
            .map(|d| d.vulns.len())
            .sum()
    }

    fn critical_vulns(&self) -> usize {
        self.results
            .iter()
            .filter_map(|r| r.deep.as_ref())
            .flat_map(|d| d.vulns.iter())
            .filter(|v| v.severity == "CRITICAL")
            .count()
    }
}

pub async fn run_tui(
    mut event_rx: UnboundedReceiver<ScanEvent>,
    stop_handle: StopHandle,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(0);
    let tick = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| render(f, &mut state))?;

        let timeout = tick
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            if !state.scan_done {
                                stop_handle.stop();
                                state.push_log("[*] Stop requested by user".to_string());
                            }
                        }
                        KeyCode::Up => state.select_up(),
                        KeyCode::Down => state.select_down(),
                        _ => {}
                    }
                }
            }
        }

        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                ScanEvent::Started { total } => {
                    state.total_probes = total;
                    state.push_log(format!("[*] Scan started — {} probes queued", total));
                }
                ScanEvent::ProbeFinished => state.probe_finished(),
                ScanEvent::OpenPort(result) => state.open_port(result),
                ScanEvent::Log(msg) => state.push_log(format!("[~] {}", msg)),
                ScanEvent::Finished { .. } => {
                    state.scan_done = true;
                    state.finished_probes = state.total_probes;
                    state.push_log(format!(
                        "[+] Scan complete — {} open ports, {} findings",
                        state.open_ports,
                        state.total_vulns()
                    ));
                }
                ScanEvent::Stopped => {
                    state.stopped = true;
                    state.push_log("[!] Scan stopped by user".to_string());
                }
                ScanEvent::Error(e) => {
                    state.push_log(format!("[ERR] {}", e));
                }
            }
        }

        if last_tick.elapsed() >= tick {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn render(f: &mut Frame, state: &mut AppState) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().bg(DARK_BG)),
        area,
    );

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(0),
            Constraint::Length(5),
        ])
        .split(area);

    render_header(f, root[0], state);
    render_main(f, root[1], state);
    render_footer(f, root[2], state);
}

fn border_block(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {} ", title),
            Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(DARK_BG))
}

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let now = utc_time();
    let status = if state.scan_done {
        if state.stopped {
            Span::styled("STOPPED", Style::default().fg(YELLOW).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("COMPLETE", Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD))
        }
    } else {
        Span::styled(
            "SCANNING",
            Style::default()
                .fg(CYAN)
                .add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
        )
    };

    let mode_tag = if state.deep_mode {
        Span::styled(" [DEEP] ", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [FAST] ", Style::default().fg(DIM_GREEN))
    };

    let logo = Paragraph::new(vec![
        Line::from(Span::styled(
            "██╗  ██╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗ ",
            Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "██║  ██║██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗",
            Style::default().fg(DIM_GREEN).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "███████║███████║   ██║   ██╔████╔██║███████║██████╔╝",
            Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(DARK_BG)),
    );

    let info = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("  v0.1.0", Style::default().fg(DIM_GREEN)),
            mode_tag,
            Span::styled("│ STATUS: ", Style::default().fg(Color::Gray)),
            status,
        ]),
        Line::from(vec![
            Span::styled("  TIME:   ", Style::default().fg(Color::Gray)),
            Span::styled(now, Style::default().fg(CYAN)),
        ]),
        Line::from(vec![
            Span::styled("  [q]uit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[s]top  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[↑↓] navigate", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(DARK_BG)),
    );

    f.render_widget(logo, cols[0]);
    f.render_widget(info, cols[1]);
}

fn render_main(f: &mut Frame, area: Rect, state: &mut AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    render_log(f, cols[0], state);
    render_right(f, cols[1], state);
}

fn render_log(f: &mut Frame, area: Rect, state: &AppState) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let start = state.logs.len().saturating_sub(inner_height);
    let items: Vec<ListItem> = state.logs[start..]
        .iter()
        .map(|line| {
            let style = if line.starts_with("[OPEN]") {
                Style::default().fg(PRIMARY)
            } else if line.starts_with("[ERR]") {
                Style::default().fg(RED)
            } else if line.starts_with("[!]") {
                Style::default().fg(YELLOW)
            } else if line.starts_with("[+]") {
                Style::default().fg(CYAN)
            } else {
                Style::default().fg(DIM_GREEN)
            };
            ListItem::new(Span::styled(line.as_str(), style))
        })
        .collect();

    f.render_widget(List::new(items).block(border_block("Live Scan Log")), area);
}

fn render_right(f: &mut Frame, area: Rect, state: &mut AppState) {
    if state.deep_mode {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(35),
                Constraint::Percentage(35),
                Constraint::Percentage(30),
            ])
            .split(area);

        render_host_list(f, rows[0], state);
        render_inspection_panel(f, rows[1], state);
        render_vuln_summary(f, rows[2], state);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);

        render_host_list(f, rows[0], state);
        render_dashboard(f, rows[1], state);
    }
}

fn render_host_list(f: &mut Frame, area: Rect, state: &mut AppState) {
    let items: Vec<ListItem> = state
        .results
        .iter()
        .map(|r| {
            let vuln_tag = r.deep.as_ref().map(|d| {
                let c = d.vulns.iter().filter(|v| v.severity == "CRITICAL").count();
                let h = d.vulns.iter().filter(|v| v.severity == "HIGH").count();
                if c > 0 {
                    format!(" !!{}", c)
                } else if h > 0 {
                    format!(" !{}", h)
                } else if !d.vulns.is_empty() {
                    format!(" ~{}", d.vulns.len())
                } else {
                    String::new()
                }
            }).unwrap_or_default();

            let label = format!(
                "{:<15} :{:<5} {:<12}{}",
                r.host.to_string(),
                r.port,
                r.fingerprint.service,
                vuln_tag
            );

            let style = if r.deep.as_ref().map(|d| d.vulns.iter().any(|v| v.severity == "CRITICAL")).unwrap_or(false) {
                Style::default().fg(RED).add_modifier(Modifier::BOLD)
            } else if r.deep.as_ref().map(|d| d.vulns.iter().any(|v| v.severity == "HIGH")).unwrap_or(false) {
                Style::default().fg(ORANGE)
            } else {
                Style::default().fg(PRIMARY)
            };

            ListItem::new(Span::styled(label, style))
        })
        .collect();

    let list = List::new(items)
        .block(border_block("Host Details"))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(0, 60, 20))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut state.list_state);
}

fn render_inspection_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let selected = state.results.get(state.selected);

    let lines: Vec<Line> = match selected {
        None => vec![Line::from(Span::styled(
            "  No host selected",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(r) => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("  Host     ", Style::default().fg(Color::Gray)),
                    Span::styled(r.host.to_string(), Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  Port     ", Style::default().fg(Color::Gray)),
                    Span::styled(r.port.to_string(), Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  Service  ", Style::default().fg(Color::Gray)),
                    Span::styled(r.fingerprint.service.clone(), Style::default().fg(CYAN)),
                ]),
            ];

            if let Some(v) = &r.fingerprint.version {
                lines.push(Line::from(vec![
                    Span::styled("  Version  ", Style::default().fg(Color::Gray)),
                    Span::styled(v.clone(), Style::default().fg(YELLOW)),
                ]));
            }
            if let Some(p) = &r.fingerprint.product {
                lines.push(Line::from(vec![
                    Span::styled("  Product  ", Style::default().fg(Color::Gray)),
                    Span::styled(p.clone(), Style::default().fg(DIM_GREEN)),
                ]));
            }
            if let Some(rtt) = r.rtt_ms {
                lines.push(Line::from(vec![
                    Span::styled("  RTT      ", Style::default().fg(Color::Gray)),
                    Span::styled(format!("{} ms", rtt), Style::default().fg(DIM_GREEN)),
                ]));
            }
            if let Some(deep) = &r.deep {
                if let Some(os) = &deep.os_hint {
                    lines.push(Line::from(vec![
                        Span::styled("  OS Hint  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{} ({})", os.guess, os.confidence),
                            Style::default().fg(YELLOW),
                        ),
                    ]));
                }
                lines.push(Line::from(vec![
                    Span::styled("  Findings ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{} total", deep.vulns.len()),
                        if deep.vulns.iter().any(|v| v.severity == "CRITICAL") {
                            Style::default().fg(RED).add_modifier(Modifier::BOLD)
                        } else if deep.vulns.iter().any(|v| v.severity == "HIGH") {
                            Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(YELLOW)
                        },
                    ),
                ]));
            }
            if let Some(banner) = &r.fingerprint.raw_banner {
                let truncated = if banner.len() > 60 { &banner[..60] } else { banner };
                lines.push(Line::from(vec![
                    Span::styled("  Banner   ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        truncated.replace('\n', " ").replace('\r', ""),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
            lines
        }
    };

    let para = Paragraph::new(lines)
        .block(border_block("Inspection Panel"))
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_vuln_summary(f: &mut Frame, area: Rect, state: &AppState) {
    let selected = state.results.get(state.selected);

    let lines: Vec<Line> = match selected.and_then(|r| r.deep.as_ref()).filter(|d| !d.vulns.is_empty()) {
        None => {
            vec![Line::from(Span::styled(
                "  No findings for selected host",
                Style::default().fg(Color::DarkGray),
            ))]
        }
        Some(deep) => deep
            .vulns
            .iter()
            .map(|v| {
                let sev_style = match v.severity {
                    "CRITICAL" => Style::default().fg(RED).add_modifier(Modifier::BOLD),
                    "HIGH" => Style::default().fg(ORANGE).add_modifier(Modifier::BOLD),
                    "MEDIUM" => Style::default().fg(YELLOW),
                    "LOW" => Style::default().fg(CYAN),
                    _ => Style::default().fg(Color::Gray),
                };
                Line::from(vec![
                    Span::styled(format!("  [{:8}] ", v.severity), sev_style),
                    Span::styled(v.title.clone(), Style::default().fg(Color::White)),
                ])
            })
            .collect(),
    };

    let title = format!(
        "Vuln Summary  [total:{} crit:{} high:{}]",
        state.total_vulns(),
        state.critical_vulns(),
        state
            .results
            .iter()
            .filter_map(|r| r.deep.as_ref())
            .flat_map(|d| d.vulns.iter())
            .filter(|v| v.severity == "HIGH")
            .count()
    );

    let para = Paragraph::new(lines)
        .block(border_block(&title))
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_dashboard(f: &mut Frame, area: Rect, state: &AppState) {
    let eta_str = match state.eta_secs() {
        Some(s) if s > 3600 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        Some(s) if s > 60 => format!("{}m {}s", s / 60, s % 60),
        Some(s) => format!("{}s", s),
        None if state.scan_done => "Done".to_string(),
        None => "Calculating…".to_string(),
    };

    let elapsed = state.started_at.elapsed();
    let elapsed_str = format!("{}:{:02}", elapsed.as_secs() / 60, elapsed.as_secs() % 60);

    let text = vec![
        Line::from(vec![
            Span::styled("  Probes Done  ", Style::default().fg(Color::Gray)),
            Span::styled(
                state.finished_probes.to_string(),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" / ", Style::default().fg(Color::DarkGray)),
            Span::styled(state.total_probes.to_string(), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("  Open Ports   ", Style::default().fg(Color::Gray)),
            Span::styled(
                state.open_ports.to_string(),
                Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  PPS          ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.0}", state.last_pps),
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ETA          ", Style::default().fg(Color::Gray)),
            Span::styled(eta_str, Style::default().fg(CYAN)),
        ]),
        Line::from(vec![
            Span::styled("  Elapsed      ", Style::default().fg(Color::Gray)),
            Span::styled(elapsed_str, Style::default().fg(DIM_GREEN)),
        ]),
    ];

    let para = Paragraph::new(text)
        .block(border_block("Dashboard"))
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_footer(f: &mut Frame, area: Rect, state: &AppState) {
    let ratio = state.progress_ratio();
    let pct = (ratio * 100.0) as u16;

    let vuln_info = if state.deep_mode && state.total_vulns() > 0 {
        format!(
            " │ {} findings ({} CRIT)",
            state.total_vulns(),
            state.critical_vulns()
        )
    } else {
        String::new()
    };

    let label = if state.scan_done {
        format!("100% — {} open ports{}", state.open_ports, vuln_info)
    } else {
        format!(
            "{pct}% — {}/{} probes — {:.0} pps{}",
            state.finished_probes, state.total_probes, state.last_pps, vuln_info
        )
    };

    let gauge_color = if state.stopped {
        YELLOW
    } else if state.scan_done {
        PRIMARY
    } else {
        CYAN
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(Span::styled(
                    " Scan Progress ",
                    Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER))
                .style(Style::default().bg(DARK_BG)),
        )
        .gauge_style(
            Style::default()
                .fg(gauge_color)
                .bg(Color::Rgb(0, 30, 10))
                .add_modifier(Modifier::BOLD),
        )
        .ratio(ratio)
        .label(Span::styled(
            label,
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ))
        .use_unicode(true);

    f.render_widget(gauge, area);
}

fn utc_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "{:02}:{:02}:{:02} UTC",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}
