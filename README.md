# DPI Engine — Deep Packet Inspection System

> High-performance network traffic analysis engine with multi-threaded architecture, real-time flow classification, and rule-based filtering.

---

## Overview

A production-grade Deep Packet Inspection system built in **C++17** that captures, parses, classifies, and filters network traffic at the packet level. Supports both single-threaded and multi-threaded execution modes, processing live PCAP captures to identify applications, extract TLS metadata, and enforce blocking rules.

```
Input PCAP → [Parse] → [Classify] → [Enforce Rules] → Output PCAP + Report
```

---

## Key Features

- **Protocol Parsing** — Full Ethernet → IPv4 → TCP/UDP header deconstruction
- **TLS SNI Extraction** — Identifies destination domains from encrypted HTTPS handshakes without decryption
- **Application Classification** — Maps flows to known apps (YouTube, Facebook, Google, GitHub, etc.)
- **Flow-Level Blocking** — Stateful, five-tuple-based rule enforcement (by IP, app type, or domain)
- **Multi-threaded Pipeline** — Load Balancer + Fast Path thread pool with consistent hashing for flow affinity
- **PCAP I/O** — Full read/write support for Wireshark-compatible capture files

---

## Technical Stack

| Area | Details |
|---|---|
| Language | C++17 |
| Concurrency | `std::thread`, `std::mutex`, `std::condition_variable` |
| Data Structures | Hash maps, thread-safe producer-consumer queues |
| Protocols | Ethernet, IPv4, TCP, UDP, TLS 1.0–1.3, HTTP/1.1 |
| Build | `g++` / `clang++`, no external dependencies |
| Platform | Linux / macOS |

---

## Architecture

### Single-Threaded Mode
Straightforward sequential pipeline — ideal for analysis and debugging.

### Multi-Threaded Mode

```
Reader Thread
     │
     ├─── hash(5-tuple) % N ───┐
     ▼                         ▼
  LB Thread 0             LB Thread 1
     │                         │
  ┌──┴──┐                   ┌──┴──┐
  FP0   FP1                 FP2   FP3
  └──┬──┘                   └──┬──┘
     └──────────┬──────────────┘
                ▼
         Output Writer Thread
```

- **Load Balancers (LB)** distribute packets across Fast Path workers
- **Fast Paths (FP)** each own an isolated flow table — no cross-thread locking on hot paths
- **Consistent hashing** guarantees all packets of a TCP connection land on the same FP thread, enabling correct stateful tracking

---

## Core Components

### `pcap_reader` — PCAP File I/O
Parses binary PCAP format (global header + per-packet headers), validates magic bytes, and streams raw packets for processing.

### `packet_parser` — Protocol Dissection
Decodes raw bytes into structured fields: MAC addresses, IPs, ports, TCP flags, sequence numbers. Handles network-to-host byte order conversion (`ntohs` / `ntohl`).

### `sni_extractor` — TLS Deep Inspection
Navigates the TLS Client Hello binary structure to extract the SNI hostname — enabling domain identification of encrypted HTTPS traffic **without decryption**.

```
TLS Record (0x16) → Handshake (0x01) → Extensions → SNI (type 0x0000) → hostname
```

### `connection_tracker` — Stateful Flow Management
Maintains per-flow state keyed on the five-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`. Once a flow is classified or blocked, the decision applies to all subsequent packets.

### `rule_manager` — Policy Enforcement
Evaluates packets against three rule types:

| Rule | Example | Scope |
|---|---|---|
| IP Block | `192.168.1.50` | All traffic from source IP |
| App Block | `YouTube` | All classified YouTube flows |
| Domain Block | `tiktok` | SNI substring match |

### `thread_safe_queue` — Lock-Based Queue
Template producer-consumer queue using `std::mutex` + `std::condition_variable`. Producers signal on push; consumers block-wait efficiently without busy-looping.

---

## Sample Output

### Multi-threaded with Blocking Rules Applied

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4     ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked IP: 192.168.1.50
[Rules] Blocked app: YouTube
[Rules] Blocked domain: tiktok
Opened PCAP file: test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
  Link type: 1 (Ethernet)
[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                           ║
║ Total Bytes:                5738                           ║
║ TCP Packets:                  73                           ║
║ UDP Packets:                   4                           ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    70                           ║
║ Dropped:                       7                           ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                           ║
║   LB1 dispatched:             24                           ║
║   FP0 processed:              53                           ║
║   FP1 processed:               0                           ║
║   FP2 processed:               0                           ║
║   FP3 processed:              24                           ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########            ║
║ Unknown              16  20.8% ####                  ║
║ DNS                   4   5.2% #                     ║
║ Twitter/X             3   3.9%                       ║
║ HTTP                  2   2.6%                       ║
║ GitHub                1   1.3%                       ║
║ Amazon                1   1.3%                       ║
║ Instagram            1   1.3%                       ║
║ Discord              1   1.3%                       ║
║ Facebook             1   1.3%                       ║
║ YouTube              1   1.3%                       ║
║ Apple                1   1.3%                       ║
║ Zoom                 1   1.3%                       ║
║ Google               1   1.3%                       ║
║ Telegram             1   1.3%                       ║
║ TikTok               1   1.3%                       ║
║ Spotify              1   1.3%                       ║
║ Cloudflare           1   1.3%                       ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - example.com → HTTPS
  - open.spotify.com → Spotify
  - www.microsoft.com → Twitter/X
  - github.com → GitHub
  - www.facebook.com → Facebook
  - zoom.us → Zoom
  - httpbin.org → HTTPS
  - www.youtube.com → YouTube (BLOCKED)
  - www.instagram.com → Instagram
  - discord.com → Discord
  - web.telegram.org → Telegram
  - www.apple.com → Apple
  - twitter.com → Twitter/X
  - www.google.com → Google
  - www.amazon.com → Amazon
  - www.cloudflare.com → Cloudflare
  - www.netflix.com → Twitter/X
  - www.tiktok.com → TikTok (BLOCKED)

Output written to: output.pcap
```

**Key Results:**
- **Blocking Rules in Action**: 7 packets dropped by applied rules (YouTube app, domain tiktok, IP 192.168.1.50)
- **Load Distribution**: LB0 dispatched 53 packets to FP0, LB1 dispatched 24 packets to FP3
- **18 Unique Domains Extracted** via TLS SNI from encrypted connections
- **15 Application Types Identified** including HTTPS, DNS, social media, and streaming services

---

## Build & Run

**Single-threaded:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Multi-threaded:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Demo script:**
```bash
./run-st-dpi
```

**Usage:**
```bash
# Single-threaded demo
./run-st-dpi

# Single-threaded manual run
./dpi_simple test_dpi.pcap output.pcap

# Multi-threaded baseline
./dpi_engine test_dpi.pcap output.pcap

# With blocking rules (drops matching packets from output)
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --block-domain tiktok

# Configure Load Balancer and Fast Path thread counts
./dpi_engine test_dpi.pcap output.pcap --lbs 4 --fps 4
```

**Blocking Rules Behavior:**
- `--block-app YouTube` — Drops all flows classified as YouTube
- `--block-ip 192.168.1.50` — Drops all packets from/to that IP
- `--block-domain tiktok` — Drops flows matching domain SNI substring "tiktok"

Dropped packets are NOT written to the output PCAP file.

> Note: `output.pcap`, `dpi_simple`, and `dpi_engine` are generated artifacts and should not be committed to source control. They are ignored by `.gitignore`. 

---

## What I Learned / Built

- Designed a **zero-copy packet pipeline** where raw bytes flow from reader to writer with minimal allocation
- Implemented **binary protocol parsing** by hand for Ethernet, IP, TCP, and TLS — no libraries
- Used **consistent hashing** to solve the flow-affinity problem in a multi-producer, multi-consumer system
- Built a **thread-safe queue** from primitives to avoid lock contention on the hot path
- Explored how **TLS SNI leaks domain metadata** despite end-to-end encryption — a real technique used in ISP-level traffic shaping

---

## Project Structure

```
packet_analyzer/
├── include/              # Headers: types, interfaces
│   ├── types.h           # FiveTuple, AppType, Flow structs
│   ├── pcap_reader.h
│   ├── packet_parser.h
│   ├── sni_extractor.h
│   ├── connection_tracker.h
│   ├── load_balancer.h
│   ├── fast_path.h
│   └── thread_safe_queue.h
├── src/
│   ├── main_working.cpp  # Single-threaded entry point
│   ├── dpi_mt.cpp        # Multi-threaded entry point
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   └── types.cpp
└── generate_test_pcap.py # Test data generator
```
