# Nebula-Scan

Nebula-Scan is an asynchronous Rust TCP scanner with a privilege-aware scan path: raw TCP SYN probing when available and a standard TCP connect fallback for ordinary users.

## Build

```powershell
cargo build --release
```

The default build does not link Npcap/WinPcap, so it works on Windows systems without `Packet.lib`.

Raw SYN support is optional:

```powershell
cargo build --release --features raw-syn
```

On Windows, raw SYN builds require the Npcap SDK or another provider of `Packet.lib` on the linker path.

## Examples

```powershell
cargo run -- --target 192.168.1.0/24 --ports 22,80,443 --concurrency 1024 --output pretty
cargo run -- --target 10.0.0.5 --ports 1-1000 --mode connect --output json
cargo run --features raw-syn -- --target 192.168.1.10 --ports 80,443 --mode syn
```

Raw SYN scanning requires elevated privileges and correct link-layer routing support on the selected interface. Use `--mode connect` when running unprivileged.
