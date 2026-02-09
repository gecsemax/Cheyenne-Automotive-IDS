Cheyenne CAN is a small experimental automotive intrusion detection system (IDS) for Linux SocketCAN that monitors a CAN bus, detects several anomaly types, and prints JSON alerts for SIEM/log pipelines.[1][2]

## Overview

- **Name:** Cheyenne CAN Intrusion Detection System (IDS)  
- Author: Max Gecse  
- Language: C (single file: `cheyenne_can.c`)  
- Platform: Linux with SocketCAN (e.g. `can0`, `vcan0`).[2][1]
- Status: Experimental, not production‑ready; intended for research, demos, and lab use.  

The IDS attaches to a CAN interface and inspects every received frame in real time, tracking basic statistics and raising JSON‑formatted alerts on suspicious activity.  

## Features

- CAN bus monitoring via Linux SocketCAN raw sockets (PF_CAN, SOCK_RAW, CAN_RAW).[1][2]
- Detection logic:
  - ID flooding / local DoS, per CAN ID with configurable frame‑rate threshold per time window.  
  - Global bus flooding / DoS, based on overall frame rate in a sliding time window.  
  - Unknown / disallowed IDs, using a user‑supplied allow‑list.  
  - Simple replay detection, via recent‑frame history per ID and exact frame matching.  
  - Value‑range anomalies on selected IDs and byte ranges, with optional DLC constraints.  
- JSON alerts to stdout with timestamp, interface, CAN ID, DLC, data bytes (hex) and human‑readable reason, suitable for ingestion by SIEM or log pipelines.[3][4]
- Basic performance statistics (frames per second, average processing time per frame, counts) emitted as JSON “stats” events.  
- Alert rate limiting with per‑key windows to avoid flooding downstream systems.  

## Build and Requirements

### Prerequisites

- Linux system with SocketCAN support enabled in the kernel.[2][1]
- Development packages providing:
  - `<linux/can.h>`, `<linux/can/raw.h>`  
  - POSIX threads (pthreads)  
- A configured CAN or virtual CAN interface (e.g. `can0`, `vcan0`).[4][1][2]

### Compilation

Example using `gcc`:

```bash
gcc -O2 -Wall -pthread -o cheyenne_can cheyenne_can.c
```

Adjust include/library paths as needed for your distribution.  

## Usage

Basic syntax:

```bash
./cheyenne_can -i <can_iface> \
  [--allow-id HEX]... \
  [--value-rule ID:byteStart-byteEnd:min-max:desc] \
  [--id-threshold N] \
  [--bus-threshold N] \
  [--window N]
```

### Examples

Monitor `can0` with default thresholds:

```bash
./cheyenne_can -i can0
```

Allow only specific IDs (others will trigger `id_spoof` alerts):

```bash
./cheyenne_can -i vcan0 --allow-id 123 --allow-id 0x456
```

Add a value‑range rule: ID `0x123`, bytes 0–1 must stay in range 0–200, described as “Speed”:

```bash
./cheyenne_can -i can0 --value-rule 0x123:0-1:0-200:Speed
```

Tighten flood thresholds and use a 2‑second window:

```bash
./cheyenne_can -i can0 --id-threshold 500 --bus-threshold 2000 --window 2
```

If `--allow-id` is not supplied, all IDs are treated as allowed and no `id_spoof` alerts are raised.  

## JSON Output

Alerts and stats are printed as one JSON object per line to stdout, making it easy to consume with tools like `jq`, Logstash, or custom collectors.[5][3]

Typical alert:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "event_type": "alert",
  "alert_type": "id_flood",
  "iface": "can0",
  "can_id": 291,
  "dlc": 8,
  "reason": "high frame rate for ID 0x123: >=1000 frames in 1 s",
  "data": "1122334455667788"
}
```

Alert types include, for example:

- `id_flood` – per‑ID flood.  
- `bus_flood` – global bus flood.  
- `id_spoof` – frame from disallowed ID.  
- `replay` – possible replay (exact match to recent frame).  
- `dlc_anomaly` – DLC outside configured min/max for a rule.  
- `value_anomaly` – payload byte out of configured range.  
- `*_suppressed` – summary when repeated alerts of a given type for an ID were rate‑limited.  

Stats event example:

```json
{
  "timestamp": "2025-01-01T12:00:05Z",
  "event_type": "stats",
  "iface": "can0",
  "frames_total": 5000,
  "frames_alerted": 10,
  "frames_dropped": 0,
  "fps": 1000.0,
  "frame_avg_usec": 15.3
}
```

Stats are emitted periodically (every few seconds) and counters are reset after each stats event.  

## Detection Logic Details

- **Per‑ID windowing:** Each CAN ID maintains a sliding window (default 1 second) with a frame counter; if the count reaches `--id-threshold`, an `id_flood` alert is generated.  
- **Global windowing:** A global window over all frames is tracked; if total frames reach `--bus-threshold`, a `bus_flood` alert is generated.  
- **Replay detection:** For each ID, the last `REPLAY_WINDOW_FRAMES` (default 32) frames are stored; if a new frame exactly matches any stored frame (ID, DLC, data), a `replay` alert is raised.  
- **Value rules:** For each configured rule, the code checks that DLC meets optional `min_dlc` / `max_dlc` constraints, then verifies that selected data bytes lie within a configured inclusive range. The first violation per frame results in a `value_anomaly` or `dlc_anomaly` alert with a descriptive message.  

## Limitations and Caveats

- Experimental proof‑of‑concept; not audited or hardened for production use.  
- Single‑threaded capture loop with global locks; heavy traffic on high‑speed CAN or CAN‑FD may stress performance.[2]
- No persistence of learned baselines, no cryptographic authentication, and no physical‑layer checks.  
- Assumes a trusted host and kernel; a compromised Linux system can still manipulate traffic before it reaches the IDS.  

## License and Contributions

This project is distributed under the license specified in `LICENSE` (see repository).  
