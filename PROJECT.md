# VPSPulse Monitoring Agent — Project Documentation

> **For AI Agents**: This document describes everything built in this codebase. Read it fully before making any changes to understand architecture, patterns, and constraints.

---

## 1. Project Overview

The **VPSPulse Monitoring Agent** (`vpsmonitoring-agent`) is a lightweight, self-contained Go daemon that runs on Linux VPS servers. It performs three core functions:

1. **Registration** — One-time onboarding using a single-use installation token issued by the backend.
2. **Heartbeat** — Periodic liveness pings to keep server status `ONLINE` in the backend.
3. **Metric Collection & Reporting** — Periodic collection and submission of system telemetry (CPU, RAM, swap, disk, network).

### Key Design Principles
- **Zero runtime dependencies** — single statically compiled binary
- **Secure credential storage** — agent credential stored in `/var/lib/vpsmonitoring-agent/agent.json` with `0600` permissions
- **Idempotent startup** — if already registered (state file exists), skips registration and uses persisted credential
- **Graceful shutdown** — responds to SIGINT/SIGTERM, stops loops cleanly

---

## 2. Directory Structure

```
vpsmonitoring-agent/
├── cmd/
│   └── agent/
│       └── main.go              # Entry point: config load → register → heartbeat + metrics loops
├── internal/
│   ├── client/
│   │   └── http_client.go       # Generic HTTP client: PostJSON with Bearer auth
│   ├── config/
│   │   └── config.go            # Env-var loading, AgentState persistence (JSON file), state save/load
│   ├── heartbeat/
│   │   └── heartbeat.go         # Heartbeat Client + Runner (periodic ticker loop)
│   ├── metrics/
│   │   ├── collector/
│   │   │   ├── collector.go     # Orchestrates all sub-collectors into MetricSnapshot
│   │   │   ├── cpu.go           # gopsutil CPU usage percent + core count + load averages
│   │   │   ├── memory.go        # gopsutil virtual memory (total, used, available, percent)
│   │   │   ├── swap.go          # gopsutil swap memory stats
│   │   │   ├── disk.go          # gopsutil disk partitions + per-mount usage
│   │   │   └── network.go       # gopsutil net IO counters (RX/TX bytes/packets/errors/drops)
│   │   ├── models/
│   │   │   └── metric.go        # MetricSnapshot struct (matches backend Metric model exactly)
│   │   └── sender/
│   │       └── sender.go        # Metric sender: POST /api/v1/agent/metrics + periodic Runner
│   └── registration/
│       └── registration.go      # Registration Client: POST /api/v1/agent/register with token
├── go.mod                       # Module: vpsmonitoring-agent, Go 1.23
├── go.sum
├── vpsmonitoring-agent-linux-amd64  # Pre-compiled Linux binary
└── README.md                    # User-facing installation guide
```

---

## 3. Agent Startup Flow

```
main.go
  │
  ├─ 1. config.Load()
  │     Reads: VPSMONITOR_BACKEND_URL (required)
  │     Reads: VPSMONITOR_INSTALLATION_TOKEN (for first registration)
  │     OR reads: VPSMONITOR_AGENT_CREDENTIAL (for subsequent runs)
  │     Falls back to state file (/var/lib/vpsmonitoring-agent/agent.json)
  │     Fails fast if neither token nor credential is available
  │
  ├─ 2. If no credential in state → Registration
  │     POST /api/v1/agent/register
  │     Body: { installation_token, hostname, ip_address, os, architecture, agent_version }
  │     Response: { agent_id, server_id, credential }
  │     Saves AgentState { agent_id, server_id, agent_credential } to state file
  │
  ├─ 3. heartbeat.Runner.Start(ctx)
  │     Immediate heartbeat on startup (transitions server to ONLINE quickly)
  │     Then ticks every HeartbeatInterval (default: 30s)
  │     POST /api/v1/agent/heartbeat  (Authorization: Bearer <credential>)
  │     Body: { timestamp, agent_version }
  │
  └─ 4. metrics.Runner.Start(ctx)
        Ticks every MetricInterval (default: 60s)
        Collects CPU, RAM, swap, disk, network via gopsutil
        POST /api/v1/agent/metrics  (Authorization: Bearer <credential>)
        Body: Full MetricSnapshot struct
```

---

## 4. Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `VPSMONITOR_BACKEND_URL` | Yes | — | Base URL of backend (e.g. http://localhost:8080) |
| `VPSMONITOR_INSTALLATION_TOKEN` | First run only | — | Single-use token from backend; consumed on registration |
| `VPSMONITOR_AGENT_CREDENTIAL` | After registration | — | Persistent bearer token for heartbeat/metrics auth |
| `VPSMONITOR_STATE_FILE` | No | `/var/lib/vpsmonitoring-agent/agent.json` | Path to persist agent state |
| `VPSMONITOR_HEARTBEAT_INTERVAL_SECONDS` | No | `30` | Seconds between heartbeat pings |
| `VPSMONITOR_METRIC_INTERVAL_SECONDS` | No | `60` | Seconds between metric snapshots |

---

## 5. API Calls Made by Agent

### 5.1 Registration — POST /api/v1/agent/register
- Auth: None (public endpoint, secured by single-use installation token in body)
- Request: { installation_token, hostname, ip_address, os, architecture, agent_version }
- Response: { data: { agent_id, server_id, credential, status } }
- Post-action: Saves agent_id, server_id, agent_credential to state file

### 5.2 Heartbeat — POST /api/v1/agent/heartbeat
- Auth: Authorization: Bearer <agent_credential>
- Request: { timestamp, agent_version }
- Success: Any HTTP 2xx (200-299)
- On 401/403: Logs auth failure, does NOT auto-retry with re-registration

### 5.3 Metrics Ingestion — POST /api/v1/agent/metrics
- Auth: Authorization: Bearer <agent_credential>
- Request: Full MetricSnapshot (cpu, memory, swap, disk array, network counters)

---

## 6. State File Format

Path: /var/lib/vpsmonitoring-agent/agent.json (or ~/.vpsmonitoring-agent/agent.json on dev)
Permissions: 0600 (owner read/write only). Directory: 0700.

```json
{
  "agent_id": "agt_abc123",
  "server_id": 7,
  "agent_credential": "<bearer-token-value>"
}
```

---

## 7. Security Properties

- Installation token is single-use (backend marks used=true after registration)
- Installation token expires (backend checks expires_at)
- Raw token not stored (agent only stores the opaque credential returned by backend)
- Credential not logged (no log statements print agent_credential)
- Credential file permissions: 0600
- No command execution (only reads system stats via gopsutil)
- No SSH key, .env, or database password collection

---

## 8. Build

```bash
# Linux production binary
GOOS=linux GOARCH=amd64 go build -o vpsmonitoring-agent-linux-amd64 ./cmd/agent

# Local dev
go build -o vpsmonitoring-agent ./cmd/agent
```

Agent version: 0.1.0 (defined in internal/config/config.go as AgentVersion constant)
