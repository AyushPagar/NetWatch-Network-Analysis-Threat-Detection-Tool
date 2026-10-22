use axum::{
    Router,
    extract::{DefaultBodyLimit, Multipart, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use pcap_parser::{Block, PcapBlockOwned, PcapError, create_reader, traits::PcapNGPacketBlock};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tokio::{fs, net::TcpListener};

const MAX_DISPLAYED_PACKETS: usize = 200;
const SENSITIVE_PORTS: [u16; 8] = [21, 22, 23, 445, 1433, 2375, 3389, 5900];
const REPEATED_DESTINATION_THRESHOLD: usize = 10;

#[derive(Clone)]
struct PacketInfo {
    number: usize,
    timestamp: String,
    source: String,
    destination: String,
    network: String,
    transport: String,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    captured_length: usize,
    original_length: usize,
    tcp_syn: bool,
}

#[derive(Clone)]
struct Finding {
    severity: &'static str,
    title: String,
    evidence: String,
}

#[derive(Clone, Default)]
struct Analysis {
    packets: usize,
    tcp: usize,
    udp: usize,
    icmp: usize,
    other: usize,
    ipv4: usize,
    ipv6: usize,
    displayed_packets: Vec<PacketInfo>,
    findings: Vec<Finding>,
    protocol_counts: HashMap<String, usize>,
    ip_counts: HashMap<String, usize>,
    destination_counts: HashMap<String, usize>,
    sensitive_port_hits: HashMap<(u16, String), (usize, usize, String, String)>,
    syn_attempts: HashMap<(String, String, u16), usize>,
    source_destinations: HashMap<String, HashSet<String>>,
    second_buckets: HashMap<i128, usize>,
}

#[derive(Clone)]
struct LatestReport {
    filename: String,
    size: usize,
    analysis: Analysis,
}
type AppState = Arc<RwLock<Option<LatestReport>>>;

fn inspect_packet(
    data: &[u8],
    number: usize,
    timestamp: String,
    original_length: usize,
) -> PacketInfo {
    let mut info = PacketInfo {
        number,
        timestamp,
        source: "Unknown".to_string(),
        destination: "Unknown".to_string(),
        network: "Unknown".to_string(),
        transport: "Unknown".to_string(),
        source_port: None,
        destination_port: None,
        captured_length: data.len(),
        original_length,
        tcp_syn: false,
    };
    if data.len() < 14 {
        info.network = "Truncated Ethernet".to_string();
        return info;
    }
    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14usize;
    while matches!(ether_type, 0x8100 | 0x88A8 | 0x9100) {
        if data.len() < offset + 4 {
            info.network = "Truncated VLAN".to_string();
            return info;
        }
        ether_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    let mut transport_offset: Option<usize> = None;
    match ether_type {
        0x0800 => {
            info.network = "IPv4".to_string();
            if data.len() < offset + 20 {
                info.transport = "Truncated IPv4".to_string();
                return info;
            }
            let version = data[offset] >> 4;
            let header_length = ((data[offset] & 0x0f) as usize) * 4;
            if version != 4 || header_length < 20 || data.len() < offset + header_length {
                info.transport = "Invalid IPv4 header".to_string();
                return info;
            }
            info.source = Ipv4Addr::new(
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            )
            .to_string();
            info.destination = Ipv4Addr::new(
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            )
            .to_string();
            let protocol = data[offset + 9];
            let fragment_offset = u16::from_be_bytes([data[offset + 6], data[offset + 7]]) & 0x1fff;
            info.transport = match protocol {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                2 => "IGMP".to_string(),
                47 => "GRE".to_string(),
                50 => "ESP".to_string(),
                51 => "AH".to_string(),
                value => format!("IP protocol {value}"),
            };
            if fragment_offset == 0 && matches!(protocol, 6 | 17) {
                transport_offset = Some(offset + header_length);
            }
        }
        0x86dd => {
            info.network = "IPv6".to_string();
            if data.len() < offset + 40 {
                info.transport = "Truncated IPv6".to_string();
                return info;
            }
            if data[offset] >> 4 != 6 {
                info.transport = "Invalid IPv6 header".to_string();
                return info;
            }
            let src: [u8; 16] = data[offset + 8..offset + 24].try_into().unwrap();
            let dst: [u8; 16] = data[offset + 24..offset + 40].try_into().unwrap();
            info.source = Ipv6Addr::from(src).to_string();
            info.destination = Ipv6Addr::from(dst).to_string();
            let mut protocol = data[offset + 6];
            let mut ipv6_transport_offset = offset + 40;
            // Walk the variable-length IPv6 extension headers before looking for TCP/UDP.
            for _ in 0..8 {
                let extension_length = match protocol {
                    0 | 43 | 60 | 135 | 139 | 140 => {
                        if data.len() < ipv6_transport_offset + 2 {
                            break;
                        }
                        Some((data[ipv6_transport_offset + 1] as usize + 1) * 8)
                    }
                    44 => Some(8),
                    51 => {
                        if data.len() < ipv6_transport_offset + 2 {
                            break;
                        }
                        Some((data[ipv6_transport_offset + 1] as usize + 2) * 4)
                    }
                    _ => None,
                };
                let Some(length) = extension_length else {
                    break;
                };
                if data.len() < ipv6_transport_offset + length {
                    break;
                }
                protocol = data[ipv6_transport_offset];
                ipv6_transport_offset += length;
            }
            info.transport = match protocol {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                58 => "ICMPv6".to_string(),
                59 => "No Next Header".to_string(),
                50 => "ESP".to_string(),
                51 => "AH".to_string(),
                value => format!("IPv6 next header {value}"),
            };
            // Extension headers are not traversed yet; only read ports when the next header is directly TCP/UDP.
            if matches!(protocol, 6 | 17) {
                transport_offset = Some(ipv6_transport_offset);
            }
        }
        0x0806 => {
            info.network = "ARP".to_string();
            info.transport = "N/A".to_string();
        }
        value => {
            info.network = format!("EtherType 0x{value:04X}");
            info.transport = "N/A".to_string();
        }
    }
    if let Some(port_offset) = transport_offset {
        if data.len() >= port_offset + 4 {
            info.source_port = Some(u16::from_be_bytes([
                data[port_offset],
                data[port_offset + 1],
            ]));
            info.destination_port = Some(u16::from_be_bytes([
                data[port_offset + 2],
                data[port_offset + 3],
            ]));
            if info.transport == "TCP" && data.len() > port_offset + 13 {
                info.tcp_syn = data[port_offset + 13] & 0x02 != 0;
            }
        } else {
            info.transport = format!("{} (truncated header)", info.transport);
        }
    }
    info
}

fn record_packet(analysis: &mut Analysis, data: &[u8], original_length: usize, timestamp: String) {
    analysis.packets += 1;
    let info = inspect_packet(data, analysis.packets, timestamp, original_length);
    *analysis
        .protocol_counts
        .entry(info.transport.clone())
        .or_default() += 1;
    if info.destination != "Unknown" {
        *analysis
            .destination_counts
            .entry(info.destination.clone())
            .or_default() += 1;
    }
    if info.source != "Unknown" {
        *analysis.ip_counts.entry(info.source.clone()).or_default() += 1;
    }
    if info.destination != "Unknown" && info.destination != info.source {
        *analysis
            .ip_counts
            .entry(info.destination.clone())
            .or_default() += 1;
    }
    if info.tcp_syn {
        if let (Some(port), true) = (info.destination_port, info.transport == "TCP") {
            *analysis
                .syn_attempts
                .entry((info.source.clone(), info.destination.clone(), port))
                .or_default() += 1;
        }
    }
    if info.source != "Unknown" && info.destination != "Unknown" {
        analysis
            .source_destinations
            .entry(info.source.clone())
            .or_default()
            .insert(info.destination.clone());
    }
    if info.transport == "TCP" || info.transport == "UDP" {
        for (direction, port) in [
            ("source", info.source_port),
            ("destination", info.destination_port),
        ] {
            if let Some(port) = port.filter(|port| SENSITIVE_PORTS.contains(port)) {
                let hit = analysis
                    .sensitive_port_hits
                    .entry((port, direction.to_string()))
                    .or_insert((
                        0,
                        info.number,
                        info.source.clone(),
                        info.destination.clone(),
                    ));
                hit.0 += 1;
            }
        }
    }
    if let Ok(seconds) = info
        .timestamp
        .split('.')
        .next()
        .unwrap_or("")
        .parse::<i128>()
    {
        *analysis.second_buckets.entry(seconds).or_default() += 1;
    }
    match info.network.as_str() {
        "IPv4" => analysis.ipv4 += 1,
        "IPv6" => analysis.ipv6 += 1,
        _ => {}
    }
    match info.transport.as_str() {
        "TCP" => analysis.tcp += 1,
        "UDP" => analysis.udp += 1,
        "ICMP" | "ICMPv6" => analysis.icmp += 1,
        _ => analysis.other += 1,
    }
    if analysis.displayed_packets.len() < MAX_DISPLAYED_PACKETS {
        analysis.displayed_packets.push(info);
    }
}

fn detect_findings(analysis: &Analysis) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ((port, direction), (count, packet_number, source, destination)) in
        &analysis.sensitive_port_hits
    {
        let title = match port {
            21 => "FTP service port observed",
            22 => "SSH service port observed",
            23 => "Telnet service port observed",
            445 => "SMB service port observed",
            1433 => "Microsoft SQL Server port observed",
            2375 => "Docker API port observed",
            3389 => "Remote Desktop port observed",
            5900 => "VNC remote access port observed",
            _ => "Sensitive service port observed",
        };
        findings.push(Finding {
            severity: if matches!(port, 23 | 2375) { "Medium" } else { "Low" },
            title: title.to_string(),
            evidence: format!("{} packet(s) used {} port {} between {} and {} (first observed in packet #{}). This port can be legitimate; review context.", count, direction, port, source, destination, packet_number),
        });
    }
    for (destination, count) in &analysis.destination_counts {
        if *count >= REPEATED_DESTINATION_THRESHOLD {
            findings.push(Finding {
                severity: "Low",
                title: "Repeated destination traffic".to_string(),
                evidence: format!("{} packets in the complete capture have destination {}. Repetition alone does not indicate an attack.", count, destination),
            });
        }
    }
    for ((source, destination, port), count) in &analysis.syn_attempts {
        if *count >= 5 {
            findings.push(Finding {
                severity: if *count >= 100 {
                    "Critical"
                } else if *count >= 20 {
                    "High"
                } else {
                    "Medium"
                },
                title: "Repeated TCP connection attempts".to_string(),
                evidence: format!(
                    "{} SYN packets from {} to {}:{} were observed in the capture.",
                    count, source, destination, port
                ),
            });
        }
    }
    for (source, destinations) in &analysis.source_destinations {
        if destinations.len() >= 10 {
            findings.push(Finding { severity: "Medium", title: "Unusually broad communication pattern".to_string(), evidence: format!("{} communicated with {} distinct destination IP addresses in the analyzed capture.", source, destinations.len()) });
        }
    }
    if analysis.second_buckets.len() >= 2 {
        let total: usize = analysis.second_buckets.values().sum();
        let average = total as f64 / analysis.second_buckets.len() as f64;
        for (second, count) in &analysis.second_buckets {
            if *count >= 10 && *count as f64 >= average * 5.0 {
                findings.push(Finding { severity: "High", title: "Packet rate spike".to_string(), evidence: format!("{} packets occurred in the one-second bucket beginning at Unix time {}; the capture-wide bucket average was {:.1} packets.", count, second, average) });
            }
        }
    }
    findings.sort_by_key(|finding| match finding.severity {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    });
    findings.truncate(100);
    findings
}

fn analyze_capture(data: &[u8]) -> Result<Analysis, String> {
    let cursor = Cursor::new(data.to_vec());
    let mut reader = create_reader(65536, cursor)
        .map_err(|_| {
            "This file is not a recognized PCAP or PCAPNG capture. It may be empty, corrupted, or use an unsupported format.".to_string()
        })?;
    let mut analysis = Analysis::default();
    let mut interfaces: VecDeque<(u64, i64)> = VecDeque::new();
    let mut legacy_nanos = false;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(packet) => {
                        let timestamp = if legacy_nanos {
                            format!("{}.{:09}", packet.ts_sec, packet.ts_usec)
                        } else {
                            format!("{}.{:06}", packet.ts_sec, packet.ts_usec)
                        };
                        record_packet(
                            &mut analysis,
                            packet.data,
                            packet.origlen as usize,
                            timestamp,
                        );
                    }
                    PcapBlockOwned::NG(block) => match block {
                        Block::InterfaceDescription(interface) => {
                            interfaces.push_back((
                                interface.ts_resolution().unwrap_or(1_000_000),
                                interface.ts_offset(),
                            ));
                        }
                        Block::EnhancedPacket(packet) => {
                            let timestamp = interfaces
                                .get(packet.if_id as usize)
                                .map(|(resolution, offset)| {
                                    let raw =
                                        ((packet.ts_high as u64) << 32) | packet.ts_low as u64;
                                    let seconds = (raw / *resolution) as i128 + *offset as i128;
                                    let micros = ((raw % *resolution) as u128 * 1_000_000
                                        / *resolution as u128)
                                        as u32;
                                    format!("{}.{:06}", seconds, micros)
                                })
                                .unwrap_or_else(|| "Timestamp unavailable".to_string());
                            record_packet(
                                &mut analysis,
                                packet.packet_data(),
                                packet.origlen as usize,
                                timestamp,
                            );
                        }
                        Block::SimplePacket(packet) => record_packet(
                            &mut analysis,
                            packet.data,
                            packet.origlen as usize,
                            "Not available".to_string(),
                        ),
                        _ => {}
                    },
                    PcapBlockOwned::LegacyHeader(header) => {
                        legacy_nanos = header.is_nanosecond_precision()
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|error| format!("Capture ended unexpectedly: {error:?}"))?;
            }
            Err(_) => {
                return Err(
                    "The capture is corrupted or contains an unsupported packet record."
                        .to_string(),
                );
            }
        }
    }
    if analysis.packets == 0 {
        return Err("The capture contains no readable packet records.".to_string());
    }
    analysis.findings = detect_findings(&analysis);
    Ok(analysis)
}

async fn home(State(state): State<AppState>) -> Html<String> {
    let mut page = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#080d17">
<title>NetWatch | Security workspace</title>
<script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.min.js"></script>
<link rel="stylesheet" href="/dashboard.css">
</head>
<body>
<header class="topbar"><div class="brand"><div class="brand-mark" aria-hidden="true">NW</div><div><h1>NETWATCH</h1><p>Network security workspace</p></div></div><div class="topbar-meta"><span class="live-dot" aria-hidden="true"></span><span>LOCAL ANALYSIS</span><span class="mode-badge">OFFLINE MODE</span></div></header>
<div class="layout">
<aside aria-label="Main navigation"><span class="nav-caption">Workspace</span><a class="active" href="/">Overview</a><a href="/upload">Analyze capture</a><a href="/packets">Packet explorer</a><a href="/traffic">Traffic statistics</a><a href="/findings">Findings</a><a href="/response">Response guide</a><a href="/reports">Reports</a><div class="sidebar-foot"><strong>Private by design</strong><span>Captures are analyzed locally by this NetWatch server.</span></div></aside>
<main>
<div class="page-heading"><div><p class="eyebrow">Security workspace / Overview</p><h2>Activity overview</h2><p class="muted">Analyze saved network captures and review evidence-backed indicators from your traffic.</p></div><span class="section-kicker">PCAP ANALYSIS</span></div>
<div class="cards">
<section class="card"><div class="metric-head"><span class="metric-label">Packets analyzed</span><span class="metric-icon" aria-hidden="true">PK</span></div><div class="number" id="total-packets">&mdash;</div><p class="muted">Latest valid capture</p></section>
<section class="card"><div class="metric-head"><span class="metric-label">TCP packets</span><span class="metric-icon" aria-hidden="true">TCP</span></div><div class="number" id="tcp-count">&mdash;</div><p class="muted">Identified in capture</p></section>
<section class="card"><div class="metric-head"><span class="metric-label">UDP packets</span><span class="metric-icon" aria-hidden="true">UDP</span></div><div class="number" id="udp-count">&mdash;</div><p class="muted">Identified in capture</p></section>
<section class="card alert-card"><div class="metric-head"><span class="metric-label">Suspicious findings</span><span class="metric-icon" aria-hidden="true">!</span></div><div class="number" id="findings-count">&mdash;</div><p class="muted">Rule matches for review</p></section>
<section class="card"><div class="metric-head"><span class="metric-label">IPv4 packets</span><span class="metric-icon" aria-hidden="true">4</span></div><div class="number" id="ipv4-count">&mdash;</div><p class="muted">Recognized network layer</p></section>
<section class="card"><div class="metric-head"><span class="metric-label">IPv6 packets</span><span class="metric-icon" aria-hidden="true">6</span></div><div class="number" id="ipv6-count">&mdash;</div><p class="muted">Recognized network layer</p></section>
<section class="card"><div class="metric-head"><span class="metric-label">ICMP packets</span><span class="metric-icon" aria-hidden="true">ICMP</span></div><div class="number" id="icmp-count">&mdash;</div><p class="muted">ICMP and ICMPv6</p></section>
</div>
<section class="panel summary-panel"><div class="summary-mark" aria-hidden="true">NW</div><div class="summary-copy"><span class="status">RULE-BASED ANALYSIS</span><h3>Latest capture summary</h3><p id="summary-text" class="muted">Upload a valid PCAP or PCAPNG file to see its analysis summary.</p><p class="muted panel-note">A rule match is evidence to investigate, not proof of malicious activity.</p></div></section>
<section class="panel" id="findings-panel"><div class="panel-head"><div><p class="eyebrow">Threat review</p><h3>Security findings</h3><p class="muted">Indicators are based on analyzed packet data and include supporting evidence.</p></div></div><p><span class="severity low">Low</span> <span class="severity medium">Medium</span> <span class="severity high">High</span> <span class="severity critical">Critical</span></p><div id="finding-results" class="muted">No capture analyzed yet.</div></section>
<section class="panel"><div class="panel-head"><div><p class="eyebrow">Network baseline</p><h3>Traffic statistics</h3><p class="muted">Protocol distribution and IP endpoint appearances.</p></div></div><div id="traffic-stats" class="muted">Statistics will appear after a capture is analyzed.</div></section>
<section class="panel" id="packet-table"><div class="panel-head"><div><p class="eyebrow">Packet explorer</p><h3>Packet details</h3><p class="muted">Up to 200 packet records from the latest capture.</p></div></div><div id="packet-results" class="muted">No packet details available yet.</div></section>
<section class="panel" id="packet-analysis"><div class="panel-head"><div><p class="eyebrow">Service status</p><h3>Connection check</h3><p class="muted">Confirm that the browser can communicate with the Rust service.</p></div></div><button class="action-button" hx-get="/status" hx-target="#htmx-result" hx-swap="innerHTML" hx-disabled-elt="this">Test server connection <span aria-hidden="true">&rarr;</span></button><div id="htmx-result" aria-live="polite"><p class="muted">Waiting for your first request.</p></div></section>
</main>
</div>
<script>
function filterPackets(){const q=document.getElementById('packet-filter')?.value.toLowerCase()||'';const t=document.getElementById('transport-filter')?.value||'';document.querySelectorAll('#packet-results tbody tr').forEach(row=>{row.hidden=(q!==''&&!row.textContent.toLowerCase().includes(q))||(t!==''&&row.dataset.transport!==t)});}
</script>
</body></html>"##.to_string();
    if let Some(report) = state.read().await.as_ref() {
        for (id, value) in [
            ("total-packets", report.analysis.packets),
            ("tcp-count", report.analysis.tcp),
            ("udp-count", report.analysis.udp),
            ("findings-count", report.analysis.findings.len()),
            ("ipv4-count", report.analysis.ipv4),
            ("ipv6-count", report.analysis.ipv6),
            ("icmp-count", report.analysis.icmp),
        ] {
            page = page.replace(
                &format!("id=\"{id}\">&mdash;"),
                &format!("id=\"{id}\">{value}"),
            );
        }
        let summary = format!(
            "{} packet records analyzed from {} ({} bytes). TCP: {}, UDP: {}, ICMP: {}, other: {}.",
            report.analysis.packets,
            escape_html(&report.filename),
            report.size,
            report.analysis.tcp,
            report.analysis.udp,
            report.analysis.icmp,
            report.analysis.other
        );
        page = page.replace(
            "Upload a valid PCAP or PCAPNG file to see its analysis summary.",
            &summary,
        );
        page = page.replace(
            "<div id=\"finding-results\" class=\"muted\">No capture analyzed yet.</div>",
            &format!(
                "<div id=\"finding-results\" class=\"muted\">{}</div>",
                finding_cards_markup(&report.analysis.findings)
            ),
        );
        page = page.replace("<div id=\"traffic-stats\" class=\"muted\">Statistics will appear after a capture is analyzed.</div>", &format!("<div id=\"traffic-stats\" class=\"muted\">{}</div>", traffic_table_markup(&report.analysis)));
        page = page.replace(
            "<div id=\"packet-results\" class=\"muted\">No packet details available yet.</div>",
            &format!(
                "<div id=\"packet-results\" class=\"muted\">{}</div>",
                packet_table_markup(&report.analysis, true)
            ),
        );
    }
    Html(page)
}
fn navigation(active: &str) -> String {
    let links = [
        ("overview", "/", "Overview"),
        ("upload", "/upload", "Analyze capture"),
        ("packets", "/packets", "Packet explorer"),
        ("traffic", "/traffic", "Traffic statistics"),
        ("findings", "/findings", "Findings"),
        ("response", "/response", "Response guide"),
        ("reports", "/reports", "Reports"),
    ];
    let mut html = String::from(
        "<aside aria-label=\"Main navigation\"><span class=\"nav-caption\">Workspace</span>",
    );
    for (key, href, label) in links {
        let current = if key == active {
            " active\" aria-current=\"page"
        } else {
            ""
        };
        html.push_str(&format!(
            "<a class=\"{}\" href=\"{}\">{}</a>",
            current.trim(),
            href,
            label
        ));
    }
    html.push_str("<div class=\"sidebar-foot\"><strong>Private by design</strong><span>Capture analysis stays on this NetWatch server.</span></div></aside>");
    html
}

fn workspace_page(active: &str, title: &str, description: &str, content: &str) -> Html<String> {
    let page = format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#080d17"><title>{} | NetWatch</title><link rel="stylesheet" href="/dashboard.css"><script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.min.js"></script></head><body><header class="topbar"><a class="brand" href="/"><span class="brand-mark">NW</span><span><h1>NETWATCH</h1><p>Network security workspace</p></span></a><div class="topbar-meta"><span class="live-dot"></span><span>LOCAL ANALYSIS</span><span class="mode-badge">OFFLINE MODE</span></div></header><div class="layout">{}<main><div class="page-heading"><div><p class="eyebrow">Security workspace / {}</p><h2>{}</h2><p class="muted page-intro">{}</p></div><span class="section-kicker">PCAP ANALYSIS</span></div>{}</main></div><script>function filterPackets(){{const q=document.getElementById('packet-filter')?.value.toLowerCase()||'';const t=document.getElementById('transport-filter')?.value||'';document.querySelectorAll('#packet-results tbody tr').forEach(row=>{{row.hidden=(q!==''&&!row.textContent.toLowerCase().includes(q))||(t!==''&&row.dataset.transport!==t)}});}}</script></body></html>"##,
        escape_html(title),
        navigation(active),
        escape_html(title),
        escape_html(title),
        escape_html(description),
        content
    );
    let page = page.replace(
        "</body>",
        &format!("{}</body>", upload_interaction_script()),
    );
    Html(page)
}

fn upload_interaction_script() -> &'static str {
    r#"<script>(()=>{const input=document.getElementById('pcap-file'),zone=document.getElementById('file-drop'),info=document.getElementById('file-info'),wrap=document.getElementById('upload-progress-wrap'),bar=document.getElementById('upload-progress'),label=document.getElementById('upload-progress-label');if(!input)return;const pretty=n=>n<1048576?(n/1024).toFixed(1)+' KiB':(n/1048576).toFixed(2)+' MiB';const show=file=>{if(!file){info.textContent='PCAP or PCAPNG · Up to 50 MiB';return;}const valid=/\.pcap(ng)?$/i.test(file.name),large=file.size>50*1024*1024;info.textContent=file.name+' · '+pretty(file.size)+(valid&&!large?' · Ready to analyze':large?' · File exceeds 50 MiB':' · Choose a .pcap or .pcapng file');info.classList.toggle('file-error',!valid||large);};input.addEventListener('change',()=>show(input.files[0]));['dragenter','dragover'].forEach(name=>zone.addEventListener(name,e=>{e.preventDefault();zone.classList.add('drag-active')}));['dragleave','drop'].forEach(name=>zone.addEventListener(name,e=>{e.preventDefault();zone.classList.remove('drag-active')}));zone.addEventListener('drop',e=>{const file=e.dataTransfer.files[0];if(file){input.files=e.dataTransfer.files;show(file);}});document.body.addEventListener('htmx:beforeRequest',e=>{if(e.detail.elt.matches('form[hx-post="/upload"]')){wrap.hidden=false;bar.value=0;label.textContent='Uploading capture...';}});document.body.addEventListener('htmx:xhr:progress',e=>{if(e.detail.elt.matches('form[hx-post="/upload"]')){const pct=e.detail.total?Math.round(100*e.detail.loaded/e.detail.total):0;bar.value=pct;label.textContent='Uploading capture... '+pct+'%';}});document.body.addEventListener('htmx:afterRequest',e=>{if(e.detail.elt.matches('form[hx-post="/upload"]')){if(e.detail.successful){bar.value=100;label.textContent='Analysis complete';input.value='';show(null);}else{wrap.hidden=true;}}});})();</script>"#
}

fn recommendation_for_finding(title: &str) -> &'static str {
    if title.contains("FTP") {
        "Confirm the service owner. Replace cleartext FTP with SFTP or FTPS, and restrict access to approved hosts at the firewall."
    } else if title.contains("Telnet") {
        "Confirm whether the service is required. Prefer SSH, disable Telnet where possible, and limit management access to a trusted network."
    } else if title.contains("SSH") {
        "Verify the destination is an approved host. Restrict SSH to trusted source networks and use key-based authentication with MFA where available."
    } else if title.contains("SMB") {
        "Check the destination and exposure. Limit SMB to required internal networks, disable SMBv1, and apply current security updates."
    } else if title.contains("SQL Server") {
        "Confirm the database should be reachable from this source. Restrict the database port to application hosts and review authentication and patch status."
    } else if title.contains("Docker") {
        "Verify the Docker API is intentional. Do not expose an unauthenticated API; bind it to a protected interface and require TLS and access controls."
    } else if title.contains("Remote Desktop") || title.contains("VNC") {
        "Confirm the remote-access service is expected. Restrict it behind a VPN or trusted source allowlist, enable MFA, and review authentication logs."
    } else if title.contains("Repeated TCP") {
        "Check whether the source is an approved health check or scanner. Review connection logs; if the attempts are unauthorized, rate-limit or block the source using your normal change process."
    } else if title.contains("Packet rate spike") {
        "Correlate the time bucket with application, deployment, and scheduled-job logs. If the load is unexpected, protect the affected service with rate limits and upstream filtering."
    } else if title.contains("communication pattern") {
        "Verify the source device and its expected destinations. Review DNS, process, and egress logs; isolate it only if independent evidence supports compromise."
    } else {
        "Compare the destination and traffic volume with your approved baseline. Confirm the business purpose before changing firewall rules or blocking traffic."
    }
}

fn packet_table_markup(analysis: &Analysis, filters: bool) -> String {
    let mut html = String::new();
    if filters {
        html.push_str("<label>Filter by IP <input id=\"packet-filter\" type=\"search\" oninput=\"filterPackets()\" placeholder=\"Source or destination IP\"></label> <label>Protocol <select id=\"transport-filter\" onchange=\"filterPackets()\"><option value=\"\">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>ICMPv6</option></select></label>");
    }
    if analysis.displayed_packets.is_empty() {
        html.push_str("<div class=\"empty\">No packet records are available. Upload a valid capture to populate this table.</div>");
        return html;
    }
    html.push_str("<div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Network</th><th>Source port</th><th>Destination port</th><th>Captured / original bytes</th></tr></thead><tbody>");
    for packet in &analysis.displayed_packets {
        let transport = escape_html(&packet.transport);
        html.push_str(&format!(
            "<tr data-transport=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"pill\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{} / {}</td></tr>",
            transport,
            packet.number,
            escape_html(&packet.timestamp),
            escape_html(&packet.source),
            escape_html(&packet.destination),
            transport,
            escape_html(&packet.network),
            packet.source_port.map(|port| port.to_string()).unwrap_or_else(|| "&mdash;".to_string()),
            packet.destination_port.map(|port| port.to_string()).unwrap_or_else(|| "&mdash;".to_string()),
            packet.captured_length,
            packet.original_length
        ));
    }
    html.push_str("</tbody></table></div>");
    html
}

fn traffic_table_markup(analysis: &Analysis) -> String {
    let mut protocols: Vec<_> = analysis.protocol_counts.iter().collect();
    protocols.sort_by(|a, b| b.1.cmp(a.1));
    let protocol_rows = protocols
        .iter()
        .map(|(name, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(name), count))
        .collect::<String>();
    let mut addresses: Vec<_> = analysis.ip_counts.iter().collect();
    addresses.sort_by(|a, b| b.1.cmp(a.1));
    let address_rows = addresses
        .iter()
        .take(50)
        .map(|(ip, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(ip), count))
        .collect::<String>();
    format!(
        "<div class=\"stat-grid\"><section class=\"panel\"><h3>Packets by protocol</h3><div class=\"table-wrap\"><table><thead><tr><th>Protocol</th><th>Packets</th></tr></thead><tbody>{}</tbody></table></div></section><section class=\"panel\"><h3>IP endpoint appearances</h3><div class=\"table-wrap\"><table><thead><tr><th>IP address</th><th>Packets</th></tr></thead><tbody>{}</tbody></table></div></section></div>",
        protocol_rows, address_rows
    )
}

fn finding_cards_markup(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "<div class=\"empty\">No configured detection rules matched this capture. This does not guarantee the capture is threat-free.</div>".to_string();
    }
    let mut html = format!(
        "<p class=\"muted\">{} finding(s) from analyzed packet data. Review the evidence before acting.</p>",
        findings.len()
    );
    for finding in findings {
        html.push_str(&format!(
            "<article class=\"finding\"><span class=\"severity {}\">{}</span><strong style=\"display:block;margin-top:8px\">{}</strong><p class=\"muted\"><b>Evidence:</b> {}</p><div class=\"response-plan\"><h4>Suggested response</h4><p>{}</p></div></article>",
            finding.severity.to_ascii_lowercase(),
            escape_html(finding.severity),
            escape_html(&finding.title),
            escape_html(&finding.evidence),
            escape_html(recommendation_for_finding(&finding.title))
        ));
    }
    html
}

async fn upload_page() -> Html<String> {
    let content = r##"<section class="panel" id="upload-panel"><div class="panel-head"><div><p class="eyebrow">Offline capture</p><h3>Upload and analyze</h3><p class="muted">Choose a PCAP or PCAPNG capture. Files are parsed as data and are never executed.</p></div></div><form hx-post="/upload" hx-encoding="multipart/form-data" hx-target="#upload-result" hx-swap="innerHTML" hx-disabled-elt="find button"><label class="file-label" for="pcap-file">Capture file</label><div class="file-drop" id="file-drop"><span class="drop-hint">Drop a capture here or choose a file</span><input id="pcap-file" type="file" name="file" accept=".pcap,.pcapng" required></div><p class="file-info muted" id="file-info" aria-live="polite">PCAP or PCAPNG &middot; Up to 50 MiB</p><div class="upload-progress-wrap" id="upload-progress-wrap" hidden><progress id="upload-progress" max="100" value="0"></progress><span id="upload-progress-label" aria-live="polite">Preparing upload...</span></div><div class="form-foot"><span>Supported: .pcap and .pcapng &middot; Maximum request size: 50 MiB</span><button class="action-button" type="submit">Analyze capture &rarr;</button></div></form><div id="upload-result" aria-live="polite"><div class="empty">No capture analyzed yet.</div></div></section>"##;
    workspace_page(
        "upload",
        "Analyze capture",
        "Validate and analyze a saved network capture.",
        content,
    )
}

async fn packets_page(State(state): State<AppState>) -> Html<String> {
    let latest = state.read().await;
    let content = if let Some(report) = latest.as_ref() {
        packet_table_markup(&report.analysis, true)
    } else {
        "<div class=\"panel empty\">Upload a valid capture to explore packet metadata.</div>"
            .to_string()
    };
    workspace_page(
        "packets",
        "Packet explorer",
        "Search the visible packet sample by IP address or protocol.",
        &content,
    )
}

async fn traffic_page(State(state): State<AppState>) -> Html<String> {
    let latest = state.read().await;
    let content = if let Some(report) = latest.as_ref() {
        traffic_table_markup(&report.analysis)
    } else {
        "<div class=\"panel empty\">Traffic statistics will appear after a capture is analyzed.</div>".to_string()
    };
    workspace_page(
        "traffic",
        "Traffic statistics",
        "Protocol totals and IP endpoint appearances measured from the latest capture.",
        &content,
    )
}

async fn findings_page(State(state): State<AppState>) -> Html<String> {
    let latest = state.read().await;
    let content = if let Some(report) = latest.as_ref() {
        format!(
            "<section class=\"panel\"><div class=\"panel-head\"><div><h3>{} finding(s)</h3><p class=\"muted\">Each card includes the observed evidence and a suggested manual response.</p></div></div>{}</section>",
            report.analysis.findings.len(),
            finding_cards_markup(&report.analysis.findings)
        )
    } else {
        "<section class=\"panel empty\">No scan results yet. Upload a capture to see findings derived from its packets.</section>".to_string()
    };
    workspace_page(
        "findings",
        "Security findings",
        "Review rule matches and practical response options.",
        &content,
    )
}

async fn response_page(State(state): State<AppState>) -> Html<String> {
    let latest = state.read().await;
    let content = if let Some(report) = latest.as_ref() {
        if report.analysis.findings.is_empty() {
            "<section class=\"panel empty\">No response recommendations were generated because no configured rules matched the latest capture.</section>".to_string()
        } else {
            let mut plans = String::new();
            for finding in &report.analysis.findings {
                plans.push_str(&format!("<article class=\"response-plan\"><span class=\"severity {}\">{}</span><h4 style=\"margin-top:10px\">{}</h4><p><b>Evidence:</b> {}<br><b>Suggested next step:</b> {}</p></article>", finding.severity.to_ascii_lowercase(), escape_html(finding.severity), escape_html(&finding.title), escape_html(&finding.evidence), escape_html(recommendation_for_finding(&finding.title))));
            }
            format!(
                "<section class=\"panel\"><h3>Response guidance for this capture</h3><p class=\"muted\">These are investigation steps, not automatic containment actions. Confirm the host, service owner, and surrounding logs before blocking traffic.</p>{}</section>",
                plans
            )
        }
    } else {
        "<section class=\"panel empty\">Upload a capture first. Response guidance will be tied to findings from that capture.</section>".to_string()
    };
    workspace_page(
        "response",
        "Response guide",
        "Practical, evidence-linked steps for investigating detected activity.",
        &content,
    )
}

async fn reports_page(State(state): State<AppState>) -> Html<String> {
    let latest = state.read().await;
    let content = if let Some(report) = latest.as_ref() {
        format!(
            "<section class=\"panel\"><p class=\"eyebrow\">Latest analysis</p><h3>{}</h3><p class=\"muted\">{} bytes · {} packet records · {} findings listed</p><div class=\"report-actions\"><a class=\"action-button\" href=\"/report.json\">Download JSON report</a><a class=\"action-button\" href=\"/report.html\">Download HTML report</a></div></section>",
            escape_html(&report.filename),
            report.size,
            report.analysis.packets,
            report.analysis.findings.len()
        )
    } else {
        "<section class=\"panel empty\">No reports are available yet. Analyze a capture to generate JSON and HTML reports.</section>".to_string()
    };
    workspace_page(
        "reports",
        "Security reports",
        "Export the latest capture analysis and its supporting evidence.",
        &content,
    )
}

async fn dashboard_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../dashboard.css"),
    )
}

async fn status() -> Html<&'static str> {
    Html(
        r#"<div class="response"><strong>Connection successful!</strong><p>HTMX sent a request and Rust returned this HTML fragment.</p><p>NetWatch server is responding correctly.</p></div>"#,
    )
}

async fn json_report(State(state): State<AppState>) -> Response {
    let latest = state.read().await;
    let Some(report) = latest.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "Analyze a capture before downloading a report.",
        )
            .into_response();
    };
    let mut protocols: Vec<_> = report.analysis.protocol_counts.iter().collect();
    protocols.sort_by(|a, b| a.0.cmp(b.0));
    let protocols_json = protocols
        .into_iter()
        .map(|(name, count)| format!("{}:{}", json_string(name), count))
        .collect::<Vec<_>>()
        .join(",");
    let mut ips: Vec<_> = report.analysis.ip_counts.iter().collect();
    ips.sort_by(|a, b| a.0.cmp(b.0));
    let ips_json = ips
        .into_iter()
        .map(|(ip, count)| format!("{}:{}", json_string(ip), count))
        .collect::<Vec<_>>()
        .join(",");
    let findings_json = report
        .analysis
        .findings
        .iter()
        .map(|finding| {
            format!(
                "{{\"severity\":{},\"title\":{},\"evidence\":{},\"suggested_response\":{}}}",
                json_string(finding.severity),
                json_string(&finding.title),
                json_string(&finding.evidence),
                json_string(recommendation_for_finding(&finding.title))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let packets_json = report.analysis.displayed_packets.iter().map(|packet| format!("{{\"number\":{},\"timestamp\":{},\"source\":{},\"destination\":{},\"network\":{},\"protocol\":{},\"source_port\":{},\"destination_port\":{},\"captured_length\":{},\"original_length\":{}}}", packet.number, json_string(&packet.timestamp), json_string(&packet.source), json_string(&packet.destination), json_string(&packet.network), json_string(&packet.transport), packet.source_port.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()), packet.destination_port.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()), packet.captured_length, packet.original_length)).collect::<Vec<_>>().join(",");
    let body = format!(
        "{{\"filename\":{},\"size_bytes\":{},\"packets_analyzed\":{},\"protocol_counts\":{{{}}},\"ip_packet_counts\":{{{}}},\"findings\":[{}],\"packets\":[{}]}}",
        json_string(&report.filename),
        report.size,
        report.analysis.packets,
        protocols_json,
        ips_json,
        findings_json,
        packets_json
    );
    let mut response = (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        body,
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_static("attachment; filename=netwatch-report.json"),
    );
    response
}

fn json_string(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

async fn html_report(State(state): State<AppState>) -> Response {
    let latest = state.read().await;
    let Some(report) = latest.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "Analyze a capture before downloading a report.",
        )
            .into_response();
    };
    let mut findings = String::new();
    for finding in &report.analysis.findings {
        findings.push_str(&format!(
            "<article class=\"finding\"><strong>{} &middot; {}</strong><p><b>Evidence:</b> {}</p><div class=\"response-plan\"><h4>Suggested response</h4><p>{}</p></div></article>",
            escape_html(finding.severity),
            escape_html(&finding.title),
            escape_html(&finding.evidence),
            escape_html(recommendation_for_finding(&finding.title))
        ));
    }
    if findings.is_empty() {
        findings.push_str("<p>No configured rules matched this capture.</p>");
    }
    let mut protocols: Vec<_> = report.analysis.protocol_counts.iter().collect();
    protocols.sort_by(|a, b| a.0.cmp(b.0));
    let protocol_rows = protocols
        .into_iter()
        .map(|(name, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(name), count))
        .collect::<String>();
    let mut ip_stats: Vec<_> = report.analysis.ip_counts.iter().collect();
    ip_stats.sort_by(|a, b| b.1.cmp(a.1));
    let ip_rows = ip_stats
        .into_iter()
        .take(50)
        .map(|(ip, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(ip), count))
        .collect::<String>();
    let document = format!(
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>NetWatch Security Report</title><style>__NETWATCH_STYLES__</style><h1>NetWatch Security Report</h1><p>Capture: <b>{}</b> &middot; {} bytes &middot; {} packet records analyzed</p><h2>Protocol statistics</h2><table><thead><tr><th>Protocol</th><th>Packets</th></tr></thead><tbody>{}</tbody></table><h2>IP packet counts (top 50)</h2><table><thead><tr><th>IP address</th><th>Observed packets</th></tr></thead><tbody>{}</tbody></table><h2>Findings ({})</h2>{}<p><small>Rule-based indicators derived from this capture; findings are not proof of malicious activity.</small></p></html>",
        escape_html(&report.filename),
        report.size,
        report.analysis.packets,
        protocol_rows,
        ip_rows,
        report.analysis.findings.len(),
        findings
    )
    .replace("__NETWATCH_STYLES__", include_str!("../dashboard.css"));
    let mut response = Html(document).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_static("attachment; filename=netwatch-report.html"),
    );
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn error_html(message: &str) -> Html<String> {
    Html(format!(
        r#"<div class="upload-error"><strong>Capture analysis failed</strong><p>{}</p></div>"#,
        escape_html(message)
    ))
}

fn analysis_html(filename: &str, size: usize, analysis: &Analysis) -> String {
    let mut rows = String::new();
    for packet in &analysis.displayed_packets {
        rows.push_str(&format!(r#"<tr data-transport="{}"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class="pill">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{} / {}</td></tr>"#,
            escape_html(&packet.transport),
            packet.number, escape_html(&packet.timestamp), escape_html(&packet.source), escape_html(&packet.destination), escape_html(&packet.transport), escape_html(&packet.network),
            packet.source_port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()), packet.destination_port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()), packet.captured_length, packet.original_length));
    }
    let more_text = if analysis.packets > MAX_DISPLAYED_PACKETS {
        format!(
            " Showing the first {} of {} packets.",
            MAX_DISPLAYED_PACKETS, analysis.packets
        )
    } else {
        String::new()
    };
    let summary = format!(
        "Analyzed {} bytes from {}. TCP: {}, UDP: {}, ICMP: {}, other: {}.{}",
        size, filename, analysis.tcp, analysis.udp, analysis.icmp, analysis.other, more_text
    );
    let mut protocol_stats: Vec<_> = analysis.protocol_counts.iter().collect();
    protocol_stats.sort_by(|a, b| b.1.cmp(a.1));
    let protocol_rows = protocol_stats
        .iter()
        .map(|(name, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(name), count))
        .collect::<String>();
    let mut ip_stats: Vec<_> = analysis.ip_counts.iter().collect();
    ip_stats.sort_by(|a, b| b.1.cmp(a.1));
    let ip_rows = ip_stats
        .iter()
        .take(20)
        .map(|(ip, count)| format!("<tr><td>{}</td><td>{}</td></tr>", escape_html(ip), count))
        .collect::<String>();
    let findings_html = finding_cards_markup(&analysis.findings);
    format!(
        r#"
<div class="upload-success"><strong>Capture analyzed successfully!</strong><p>Saved file: <code>{}</code></p><p>File size: {} bytes</p><p>Total packet records: <strong>{}</strong></p><p>TCP: {} | UDP: {} | ICMP: {} | Other: {}</p><p>IPv4: {} | IPv6: {}</p><p>Findings are preliminary rule matches, not proof of an attack.</p><p><a href="/report.json">Download JSON report</a> · <a href="/report.html">Download HTML report</a></p></div>
<div id="total-packets" class="number" hx-swap-oob="true">{}</div><div id="tcp-count" class="number" hx-swap-oob="true">{}</div><div id="udp-count" class="number" hx-swap-oob="true">{}</div><div id="ipv4-count" class="number" hx-swap-oob="true">{}</div><div id="ipv6-count" class="number" hx-swap-oob="true">{}</div><div id="icmp-count" class="number" hx-swap-oob="true">{}</div><div id="findings-count" class="number" hx-swap-oob="true">{}</div>
<p id="summary-text" class="muted" hx-swap-oob="true">{}</p><div id="finding-results" class="muted" hx-swap-oob="true">{}</div><div id="traffic-stats" class="muted" hx-swap-oob="true"><h4>Packets by protocol</h4><div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Packets</th></tr></thead><tbody>{}</tbody></table></div><h4>IP endpoint appearances (top 20)</h4><div class="table-wrap"><table><thead><tr><th>IP address</th><th>Packets</th></tr></thead><tbody>{}</tbody></table></div></div><div id="packet-results" class="muted" hx-swap-oob="true"><label>Filter by IP address <input id="packet-filter" type="search" oninput="filterPackets()" placeholder="Enter source or destination IP"></label> <label>Protocol <select id="transport-filter" onchange="filterPackets()"><option value="">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>ICMPv6</option></select></label><div class="table-wrap"><table><thead><tr><th>#</th><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Transport</th><th>Network</th><th>Source Port</th><th>Destination Port</th><th>Captured / Original Bytes</th></tr></thead><tbody>{}</tbody></table></div></div>
"#,
        escape_html(filename),
        size,
        analysis.packets,
        analysis.tcp,
        analysis.udp,
        analysis.icmp,
        analysis.other,
        analysis.ipv4,
        analysis.ipv6,
        analysis.packets,
        analysis.tcp,
        analysis.udp,
        analysis.ipv4,
        analysis.ipv6,
        analysis.icmp,
        analysis.findings.len(),
        escape_html(&summary),
        findings_html,
        protocol_rows,
        ip_rows,
        rows
    )
}

async fn upload(State(state): State<AppState>, mut multipart: Multipart) -> Html<String> {
    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => return error_html("No file was provided."),
        Err(error) => {
            eprintln!("Multipart error: {error}");
            return error_html("Could not read the upload.");
        }
    };
    let original_filename = match field.file_name() {
        Some(name) => name.to_owned(),
        None => return error_html("The uploaded file has no filename."),
    };
    let extension = match Path::new(&original_filename)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        Some(ext) if ext.eq_ignore_ascii_case("pcap") || ext.eq_ignore_ascii_case("pcapng") => {
            ext.to_ascii_lowercase()
        }
        _ => return error_html("Unsupported file type. Choose a .pcap or .pcapng file."),
    };
    let data = match field.bytes().await {
        Ok(data) if !data.is_empty() => data,
        Ok(_) => return error_html("The selected file is empty."),
        Err(error) => {
            eprintln!("File read error: {error}");
            return error_html("Could not read the uploaded file.");
        }
    };
    let analysis = match analyze_capture(&data) {
        Ok(analysis) => analysis,
        Err(message) => {
            eprintln!("Capture analysis failed: {message}");
            return error_html(&message);
        }
    };
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => return error_html("Could not generate a file identifier."),
    };
    let filename = format!("capture-{timestamp}.{extension}");
    let upload_dir = Path::new("uploads");
    if let Err(error) = fs::create_dir_all(upload_dir).await {
        eprintln!("Directory creation failed: {error}");
        return error_html("Could not prepare the upload directory.");
    }
    let destination = upload_dir.join(&filename);
    if let Err(error) = fs::write(&destination, &data).await {
        eprintln!("File save failed: {error}");
        return error_html("Could not save the analyzed capture.");
    }
    *state.write().await = Some(LatestReport {
        filename: filename.clone(),
        size: data.len(),
        analysis: analysis.clone(),
    });
    println!(
        "Analyzed {filename}: {} bytes, {} packets, TCP {}, UDP {}, ICMP {}, findings {}",
        data.len(),
        analysis.packets,
        analysis.tcp,
        analysis.udp,
        analysis.icmp,
        analysis.findings.len()
    );
    Html(analysis_html(&filename, data.len(), &analysis))
}

#[tokio::main]
async fn main() {
    let state: AppState = Arc::new(RwLock::new(None));
    let app = Router::new()
        .route("/", get(home))
        .route("/status", get(status))
        .route("/dashboard.css", get(dashboard_css))
        .route("/upload", get(upload_page).post(upload))
        .route("/packets", get(packets_page))
        .route("/traffic", get(traffic_page))
        .route("/findings", get(findings_page))
        .route("/response", get(response_page))
        .route("/reports", get(reports_page))
        .route("/report.json", get(json_report))
        .route("/report.html", get(html_report))
        .with_state(state)
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024));
    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");
    println!("NetWatch server running at http://127.0.0.1:3000");
    axum::serve(listener, app)
        .await
        .expect("NetWatch server stopped unexpectedly");
}
