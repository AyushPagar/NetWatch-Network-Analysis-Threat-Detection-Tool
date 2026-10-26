# NetWatch

NetWatch is a Rust-based web application for analyzing saved network traffic captures. Upload a PCAP or PCAPNG file to review packet metadata, traffic statistics, and rule-based security findings through a responsive dashboard.

## Features

- Upload and analyze PCAP and PCAPNG files
- Extract packet timestamps, IP addresses, protocols, ports, and lengths when available
- View protocol and IP address statistics
- Filter packet details by IP address and protocol
- Review findings with supporting evidence and suggested response guidance
- Download JSON and HTML reports
- Use a responsive dashboard with separate analysis pages

Detection results are preliminary indicators based on the analyzed capture. They do not prove that an attack occurred.

## Technology

- Rust
- Axum and Tokio
- HTML and CSS
- HTMX
- `pcap-parser`

## Requirements

Install Rust and Cargo using [rustup](https://rustup.rs/).

## Run locally

From the project folder:

```powershell
cargo run 
