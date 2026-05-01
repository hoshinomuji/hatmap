# 🎩 Hatmap
**High-Performance Asynchronous Network Reconnaissance Tool**  
*Developed by Elfaria Serfort*

**Hatmap** is a powerful network scanning utility written in **Rust**, designed for speed, memory safety, and precision. It bridges the gap between traditional tools and modern system programming by leveraging asynchronous I/O and low-level packet crafting.

---

## ✨ Features

*   🚀 **Blazing Fast:** Powered by the `tokio` runtime for non-blocking, asynchronous task scheduling.
*   🛡️ **Stealth Scanning:** Implements **TCP SYN (Half-open) Scanning** using raw packets via `libpnet` to bypass full connection logging.
*   🔍 **Deep Fingerprinting:** Advanced service detection and banner grabbing to identify product versions and OS hints.
*   🌐 **Dual-Stack Ready:** Full support for both IPv4 and IPv6 scanning, including CIDR range parsing.
*   📊 **Modern TUI:** Interactive and beautiful Terminal User Interface built with `ratatui`[cite: 1].
*   🎯 **Adaptive Logic:** Automatic RTT (Round Trip Time) calculation and dynamic timeout adjustment for unstable networks[cite: 1].
*   💾 **Flexible Output:** Supports clean table views for humans and JSON output for automation[cite: 1].

---

## 🛠️ Internal Architecture

The project is modularized for maximum maintainability:
*   **`main.rs`**: Handles CLI arguments, CIDR parsing, and result orchestration[cite: 1].
*   **`scanner.rs`**: The core engine utilizing a Producer-Consumer model with `mpsc` channels and `Semaphore` for concurrency control[cite: 1].
*   **`packet.rs`**: Handles low-level construction of TCP SYN/ACK packets and Ethernet frames[cite: 1].
*   **`fingerprint.rs`**: Manages safe banner grabbing and regex-based service identification[cite: 1].
*   **`ui.rs`**: Defines the layout and rendering logic for the interactive dashboard[cite: 1].

---

## 🚀 Getting Started

### Prerequisites
To use Raw SYN scanning, you need specific privileges or drivers:
*   **Windows:** Install [Npcap](https://nmap.org/npcap/) in "WinPcap API-compatible Mode".
*   **Linux:** Run with `sudo` or grant `CAP_NET_RAW` capabilities to the binary.

### Installation
```bash
git clone [https://github.com/hoshinomuji/hatmap.git](https://github.com/hoshinomuji/hatmap.git)
cd hatmap
cargo build --release
