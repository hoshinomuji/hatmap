# 🎩 Hatmap

**High-Performance Asynchronous Network Reconnaissance Tool**
*Developed by Elfaria Serfort*

Hatmap is a modern network scanner written in **Rust**, built for professionals who need **speed, precision, and reliability**. By combining asynchronous execution with low-level packet control, Hatmap delivers fast reconnaissance while maintaining Rust’s memory safety and performance advantages.

It is designed to sit between classic scanners and next-generation tooling — lightweight, efficient, and built for real-world workflows.

---

## ✨ Features

* 🚀 High-Speed Async Engine (Tokio)
* 🛡️ TCP SYN Half-Open Scanning
* 🔍 Service Fingerprinting & Banner Grabbing
* 🌐 IPv4 / IPv6 / CIDR Support
* 📊 Real-Time TUI Dashboard
* 🎯 Adaptive RTT Timeout Logic
* 💾 JSON + Table Output

---

## 📦 Installation

```bash
git clone https://github.com/hoshinomuji/hatmap.git
cd hatmap
cargo build --release
```

---

## ⚡ Usage

### Basic Scan

```bash
cargo run -- scanme.nmap.org --ports 22,80,443,9929
```

### SYN Scan

```
bashcargo run -- scanme.nmap.org --ports 1-1000 --syn
```

### JSON Output

```bash
cargo run -- example.com --ports 80,443 --format json
```

---

## ⚖️ Disclaimer

Use only on systems you own or have permission to test. Unauthorized scanning may violate laws or policies.
