# DeepTrace — Intelligent Mobile Network Analysis

DeepTrace is a real-time troubleshooting tool for mobile network engineers.
It ingests core-network PCAPs, UE-side radio traces (Groundhog / CovMo) and
vendor-native IMS traces (Huawei Service Trace `.zip` and Performance Trace
`.ptmf`), correlates control-plane and user-plane events across 2G/3G/4G/5G,
runs ~25 deterministic analysers over the data, and asks an LLM of your
choice to write a final root-cause narrative.

Designed for *the working day*, not for archival: at any moment the disk
holds at most one active case, and subscriber identifiers are pseudonymised
at every ingestion boundary so raw IMSIs / MSISDNs never reach disk, the
API, or the LLM provider.

---

## 🏗️ Architecture at a glance

| Layer | Component |
|---|---|
| **Frontend** | React 18 single-page app (Recharts + Mermaid). Served by nginx as a static bundle. |
| **API** | FastAPI on `127.0.0.1:8000`, fronted by nginx on `:80`. |
| **DPI** | TShark for protocol field extraction, Scapy for lightweight flow assembly. |
| **Analysers** | 16 Python modules in `backend/analysis/` + 4 in `backend/analytics/` + the radio-RCA detector pack in `backend/app/radio_rca/`. |
| **AI** | Provider-agnostic LLM layer. Pick one of Moonshot, OpenAI, Anthropic, or Google Gemini from `/admin/llm`. |
| **Privacy** | Per-process HMAC pseudonyms for IMSI/MSISDN/GUTI/TMSI/IMEI/UE-IP + nightly restart + auto-wipe on every new case. |

---

## 🚀 What it does

### Inputs accepted

| Source | Formats | Where the parser lives |
|---|---|---|
| **Core PCAP** | `.pcap`, `.pcapng` (≤500 MB, configurable) | [backend/app/pcap_parser.py](backend/app/pcap_parser.py) |
| **Radio trace (Groundhog/CovMo)** | `.html`, `.htm`, `.csv`, `.xls`, `.xlsx`, `.json`, `.xml` | [backend/app/groundhog/](backend/app/groundhog/) |
| **Huawei IMS Service Trace** | `.zip` exported from the Huawei tracing tool (frames + `index.files/`) | [backend/app/imstrace/huawei_html.py](backend/app/imstrace/huawei_html.py) |
| **Huawei IMS NE binary trace** | `.ptmf` (PTMF, magic `0xF634F634`) from CSCF / SBC / ATS | [backend/app/imstrace/huawei_ptmf.py](backend/app/imstrace/huawei_ptmf.py) |

A *case* can hold one PCAP **or** one Groundhog **or** one Huawei IMS file
(either `.zip` or `.ptmf`). Uploading a new case auto-wipes the previous
one — at most one case lives on disk at a time.

### Protocols decoded

- **5G SA** — NGAP (N2), PFCP (N4), HTTP/2 SBI, NAS-5GS
- **4G LTE** — S1-AP, GTP-v2-C, GTP-U, Diameter (Gx, Gy, Rx, S6a, Cx)
- **VoLTE / VoNR** — SIP (with full SDP, Authorization, Via/Route chains), RTP, RTCP
- **Legacy** — SS7 over IP (M3UA, SCCP, TCAP, MAP)
- **Radio (Groundhog)** — RRC events, RLF, handovers, RSRP/RSRQ/SINR/CQI/BLER, HARQ, MCS, throughput

### Analysers (the meat)

Every analyser surfaces a section in the LLM prompt that's only included
when its data is present, plus structured findings in the dashboard.

| Analyser | What it produces |
|---|---|
| **PFCP / N4** ([pfcp_analyzer.py](backend/analysis/pfcp_analyzer.py)) | Per-SEID session outcomes, association setup/release tallies, heartbeat-path-down detection, full 3GPP TS 29.244 cause map. |
| **Diameter application-level** ([diameter_analyzer.py](backend/analysis/diameter_analyzer.py)) | Per-application (Cx, S6a, Gx, Rx, Gy, Sh) success/failure rate with the top result codes. |
| **Per-subscriber session timeline** ([subscriber_tracker.py](backend/analytics/subscriber_tracker.py)) | Chronological journey per `SUB_*` pseudonym across NAS / SIP / Diameter (attach → bearer setup → INVITE → HO → drop). |
| **Handover quality** ([ho_quality_analyzer.py](backend/analysis/ho_quality_analyzer.py)) | Classifies S1 vs X2 vs Xn vs N2, measures HO preparation latency (HandoverRequired → HandoverNotify), tracks 5G beam management when available. |
| **5G slicing** ([slicing_analyzer.py](backend/analysis/slicing_analyzer.py)) | Per S-NSSAI and per QFI activity + failure rate. |
| **5G SBI errors** ([sbi_analyzer.py](backend/analysis/sbi_analyzer.py)) | Parses HTTP/2 ProblemDetails JSON to turn `:status: 400` into actionable reasons (`UE_ALREADY_REACHABLE`, `RESOURCE_BUSY`, …). |
| **Trend / pattern detection** ([trend_detector.py](backend/analytics/trend_detector.py)) | Sliding-window recurring failure causes, failure bursts, cell-cohort failures. |
| **Voice / IMS reconstruction** | Full call state machine ([call_builder.py](backend/analysis/call_builder.py)), SDP/codec ([sdp_parser.py](backend/analysis/sdp_parser.py), [codec_analyzer.py](backend/analysis/codec_analyzer.py)), precondition ([precondition_analyzer.py](backend/analysis/precondition_analyzer.py)), ringback ([ringback_analyzer.py](backend/analysis/ringback_analyzer.py)), RTP quality ([rtp_quality.py](backend/analysis/rtp_quality.py)), one-way audio / silent call detection, SRVCC/CSFB ([handover_analyzer.py](backend/analysis/handover_analyzer.py)). |
| **Radio RCA detectors** ([detectors.py](backend/app/radio_rca/detectors.py)) | 13 deterministic detectors: RLF impacting call, HO failure, paging failure, coverage degradation, RRC reestablishment / reconfig failure / reconfig latency, abnormal release, E-RAB setup failure, SgNB addition failure, high HARQ NACK, CSFB. |
| **AMC / link-adaptation distributions** ([groundhog/summary.py](backend/app/groundhog/summary.py)) | CQI band histogram (poor/fair/good/excellent), DL BLER bands, MCS bands (QPSK / 16QAM / 64QAM), HARQ ACK/NACK ratio. |
| **Vendor cause codes** ([decode/vendor_codes.py](backend/decode/vendor_codes.py)) | Nokia MSS (X.int hex), Huawei IMS proprietary text patterns, Ericsson MSC-S/MGW/RNC/BSC/SBG/OCS reason strings. |
| **Cross-plane correlation** ([correlation/correlate.py](backend/app/correlation/correlate.py)) | Aligns UE-side radio events to core signaling on timing and identity (cell ID, IMSI pseudonym). Outputs `correlation_report.json` per case. |

### KPI quick reference

| Category | KPI | Notes |
|---|---|---|
| **Voice** | Jitter | RFC 3550 mean inter-arrival jitter, warning > 30 ms |
| **Voice** | Packet loss | Sequence-number gap detection, critical > 2 % |
| **Voice** | MOS-LQE | ITU-T G.107 E-model |
| **Voice** | Post-dial delay | INVITE → 180 Ringing |
| **Signaling** | Setup success rate | Per procedure (RRC, S1AP, NGAP, Cx, S6a, …) |
| **Radio** | CQI / BLER / MCS distribution | Bucketed bands per cell |
| **Radio** | HARQ NACK ratio | ACK vs NACK across the trace |

---

## 🤖 AI-driven RCA

The LLM gets a structured prompt containing every analyser section, the
deterministic radio findings, and a strict instruction set ("only cite
evidence present in the trace; if unprovable, say INCONCLUSIVE").
It returns a JSON object with:

- `classification` — `ESTABLISHED` / `CANCELLED_BY_CALLER` / `REJECTED` / `INCOMPLETE` / `INCONCLUSIVE`
- `health_score` 0–100 and `health_status`
- `executive_narrative` — 3-4 sentence summary
- `root_causes[]` — with confidence %, evidence refs, 3GPP spec references
- `pattern_matches[]` — known 3GPP failure templates
- `recommendations[]`
- `sequence_diagram` — Mermaid (overridden by a deterministic builder for PCAP / Huawei cases so it reflects real messages, not LLM hallucination)

### LLM provider configuration

There is no LLM key in the repo or env. Operators configure it at runtime
through `/admin/llm` (HTTP Basic Auth, credentials set during `bootstrap.sh`).
Supported providers:

- **Moonshot AI** (Kimi)
- **OpenAI** (any chat-completions-compatible endpoint)
- **Anthropic** (Claude)
- **Google** (Gemini)

The page also has a one-click **Test** button that fires a `ping → pong`
round-trip and shows latency + the model's sample reply.

---

## 🔒 Privacy & data handling

DeepTrace is intentionally **real-time only** — at any moment the disk holds
at most the active case.

| Layer | Mechanism |
|---|---|
| **In-memory** | Daily restart at 23:00 UTC (`/etc/cron.d/deeptrace-restart`) wipes `analyses` dict, LLM response cache, and the per-process pseudonym keyspace. |
| **On-disk** | Startup wipe + new-case wipe (`case_manager.wipe_all_cases()`) — running `POST /api/cases` purges every prior `backend/artifacts/<case_id>/` and any leftover uploads. |
| **Subscriber IDs** | HMAC-SHA256 pseudonyms (`IMSI_xxxxxxxx`, `MSISDN_xxxxxxxx`, `SUB_N`, …) applied at the ingestion boundary in [groundhog/anonymise.py](backend/app/groundhog/anonymise.py), [imstrace/huawei_html.py](backend/app/imstrace/huawei_html.py), [imstrace/huawei_ptmf.py](backend/app/imstrace/huawei_ptmf.py), [analytics/subscriber_tracker.py](backend/analytics/subscriber_tracker.py). |
| **Secrets** | LLM API key in `backend/config/llm_config.json` (mode 600). Admin bcrypt hash in `backend/.env` (mode 600). Neither is in git. |
| **Auth** | `/admin/llm` requires HTTP Basic against the bcrypt-hashed credential. |

If a feature would store user data beyond the active case, it's intentionally
not implemented (the previous "Compare" page that listed historic cases was
removed for this reason).

---

## 📱 Dashboard

Open the dashboard at `http://<host>/`. Upload one of three trace types via
the landing cards, watch the WebSocket progress bar, then switch between:

- **🔍 Analysis** — LLM RCA: classification, health, narrative, root-causes-with-evidence, recommendations
- **📡 Radio** — Groundhog KPIs, distribution bands, deterministic radio findings
- **📊 Statistics** — Protocol mix, technology mix, flow counts
- **📞 Voice & IMS** — Per-call rows, registrations, codec / precondition / ringback findings, RTP quality
- **🧬 Diagrams** — Swim-lane `FlowDiagram` driven by `message_sequence` + Mermaid sequence diagram (deterministic for PCAP & Huawei cases, LLM-generated otherwise)
- **🌐 Flows** — Per-5-tuple drill-down with bandwidth and session correlation

Header buttons: **📄 Report** (case-aware print-to-PDF at `/report/<case_id>`)
and **🔄 New Analysis** (auto-wipes the current case).

---

## 🌐 HTTP endpoints

| Method · Path | Purpose |
|---|---|
| `GET /api/health` | Liveness probe |
| `POST /api/cases` | Create a new case (wipes any previous) |
| `GET /api/cases/{case_id}` | Case metadata |
| `POST /api/cases/{case_id}/upload?file_kind={pcap|groundhog|huawei_ims}` | Upload a trace |
| `POST /api/cases/{case_id}/analyze` | Trigger analysis (booleans for pcap / groundhog / correlation / final RCA) |
| `GET /api/analysis/{case_id}` | Poll analysis state + results |
| `GET /api/flows/{job_id}` | Paginated flows |
| `WS /ws/{job_id}` | Real-time progress stream |
| `POST /api/chat/query` | Ask follow-up questions of the current case |
| `GET /api/admin/llm/config` *(Basic Auth)* | Redacted current LLM config |
| `PUT /api/admin/llm/config` *(Basic Auth)* | Save provider/model/key |
| `POST /api/admin/llm/test` *(Basic Auth)* | Test config without persisting |
| `GET /admin/llm` *(Basic Auth)* | Admin HTML page |
| `GET /report/{case_id}` | Print-friendly HTML report (browser → Save as PDF) |

---

## 🛠️ Setup & installation

DeepTrace provides automated one-shot bootstrap scripts for both major Linux distribution families.

> [!NOTE]
> Run the bootstrap as a normal user with `sudo` privileges (not directly as `root`), because services and file ownership are bound to your user account.

### 🐧 Red Hat / CentOS / Rocky Linux / AlmaLinux / Fedora

```bash
git clone https://github.com/s-ttp/DeepTrace.git
cd DeepTrace
./bootstrap-rhel.sh
```
*(You can also run `./bootstrap.sh`; it automatically detects Red Hat family distributions and delegates to `bootstrap-rhel.sh`).*

**What `bootstrap-rhel.sh` automates (100% hands-free):**
1. **Repositories**: Enables EPEL and CRB / PowerTools repos automatically.
2. **System Dependencies**: Installs `gcc`, `gcc-c++`, `make`, `git`, `libpcap-devel`, `libxml2-devel`, `libxslt-devel`, `libffi-devel`, `openssl-devel`, `cronie`, `policycoreutils-python-utils`.
3. **Packet Capture**: Installs `wireshark-cli` (provides `tshark` and `dumpcap`), grants non-root packet-capture capabilities (`cap_net_raw,cap_net_admin+eip`), and adds the user to the `wireshark` group.
4. **Python**: Detects or installs Python 3.9+ / 3.11 with development headers and `pip`.
5. **Node.js**: Automatically installs Node.js 20 LTS via official NodeSource RPM setup if local Node is missing or `< 18`.
6. **Backend Virtualenv**: Creates `backend/venv` and installs all dependencies (`fastapi`, `uvicorn`, `scapy`, `pandas`, `lxml`, `bcrypt`, etc.).
7. **Frontend Build**: Compiles the production React single-page bundle with memory limit safety (`768MB`).
8. **Admin Credentials**: Prompts for your web console password and writes the bcrypt hash to `backend/.env` (mode `0600`). Can be run unattended by setting `DEEPTRACE_ADMIN_PASS="your_password"`.
9. **Systemd Service**: Installs and enables `deeptrace.service` to start on boot.
10. **Nginx Reverse Proxy**: Deploys native Red Hat configuration (`/etc/nginx/conf.d/deeptrace.conf`) with self-contained API & WebSocket proxy routing.
11. **SELinux**: Applies `httpd_can_network_connect 1`, sets `httpd_sys_content_t` context on frontend files, and adjusts folder traversal permissions.
12. **Firewall**: Automatically opens HTTP port 80 in `firewalld`.
13. **Privacy Hygiene**: Schedules the nightly 23:00 wipe in `crond`.
14. **Live Verification**: Boots the stack and executes smoke tests against `/api/health`.

---

### 🐧 Debian / Ubuntu

```bash
git clone https://github.com/s-ttp/DeepTrace.git
cd DeepTrace
./bootstrap.sh
```

**What `bootstrap.sh` automates:**
1. Installs system packages via `apt-get`: `python3`, `python3-venv`, `python3-pip`, `build-essential`, `nodejs`, `npm`, `tshark`, `nginx`.
2. Grants `cap_net_raw` on `dumpcap`.
3. Creates `backend/venv` and installs Python dependencies.
4. Compiles React frontend bundle.
5. Prompts for admin credentials and writes `backend/.env` (mode `0600`).
6. Installs and enables `deeptrace.service`.
7. Installs `/etc/nginx/sites-available/deeptrace` and enables the site.
8. Installs the daily 23:00 restart cron in `/etc/cron.d/deeptrace-restart`.
9. Starts the stack and smoke-tests endpoints.

---

### 💻 Manual Installation (Development / Custom Environments)

Prerequisites: Python 3.9+, Node.js 18+, `tshark`.

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Generate the admin bcrypt hash (paste into ADMIN_PASSWORD_HASH= in .env, single-quoted)
python scripts/hash_admin_password.py

# Frontend
cd ../frontend
npm install
npm run build

# Run (foreground development mode)
cd ..
./backend/venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/`. The `/admin/llm` page needs `ADMIN_USERNAME`
and `ADMIN_PASSWORD_HASH` to be set in `backend/.env` before it will accept
auth; without them, the admin endpoints return HTTP 503 by design.

---

## 🔑 Configuring & Updating LLM API Keys

DeepTrace uses an LLM provider to generate root-cause analysis (RCA) narratives, failure classifications, and interactive troubleshooting responses. All deterministic protocol analyzers, SIP/VoLTE trackers, flow diagrams, and KPI charts work out-of-the-box even without an API key.

API keys can be added, updated, or rotated at any time using **any of the three methods below**.

### Method 1: Web Admin Interface (Recommended)

1. Open your browser to:
   ```text
   http://<server-ip>/admin/llm
   ```
2. Enter the **Admin Username** and **Password** created during the bootstrap setup.
3. Select your provider:
   * **Google Gemini** (e.g., `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-2.0-flash`)
   * **Anthropic** (e.g., `claude-3-5-sonnet-20241022`, `claude-3-opus-20240229`)
   * **OpenAI** (e.g., `gpt-4o`, `gpt-4o-mini`)
   * **Moonshot / Kimi** (e.g., `kimi-k2.5`)
4. Paste your **API Key** (and optionally custom Base URL if using an enterprise proxy or internal endpoint).
5. Click **Test Config** to perform a live probe without saving.
6. Click **Save Configuration**. The new key is hot-reloaded immediately without restarting the backend service!

---

### Method 2: REST API (Curl / Automation)

You can inspect or update the LLM configuration programmatically via HTTP Basic Auth:

```bash
# 1. Check current active provider and key status (redacted)
curl -u admin:YOUR_ADMIN_PASSWORD http://127.0.0.1/api/admin/llm/config

# 2. Test an API key before saving
curl -u admin:YOUR_ADMIN_PASSWORD -X POST http://127.0.0.1/api/admin/llm/test \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "model": "gemini-1.5-pro",
    "api_key": "YOUR_GEMINI_API_KEY"
  }'

# 3. Save / Update the LLM configuration
curl -u admin:YOUR_ADMIN_PASSWORD -X PUT http://127.0.0.1/api/admin/llm/config \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "model": "gemini-1.5-pro",
    "api_key": "YOUR_GEMINI_API_KEY"
  }'
```

---

### Method 3: Direct File Configuration

The persistent source of truth on disk is `backend/config/llm_config.json`:

```json
{
  "provider": "google",
  "model": "gemini-1.5-pro",
  "api_key": "AIzaSy...",
  "base_url": "",
  "updated_at": "2026-10-08T08:30:00Z",
  "source": "file"
}
```

* **File location**: `backend/config/llm_config.json`
* **File permissions**: Mode `0600` (readable only by the owner).
* Any edit takes effect on the next request or after `sudo systemctl restart deeptrace`.

---

### 🔄 Rotating or Resetting Admin Password

If you ever need to change or reset the web console credentials for `/admin/llm`:

```bash
cd backend
# Generate a new bcrypt hash
./venv/bin/python scripts/hash_admin_password.py
# Edit backend/.env and replace ADMIN_PASSWORD_HASH:
# ADMIN_PASSWORD_HASH='$2b$12$...'
sudo systemctl restart deeptrace
```

---

## 🔧 Day-2 operations

```bash
# Logs (follow live)
sudo journalctl -u deeptrace -f

# Restart
sudo systemctl restart deeptrace

# Status
systemctl status deeptrace

# Re-run bootstrap after a `git pull` (rebuilds bundle, refreshes nginx + unit)
./bootstrap.sh
```

The nightly cron at 23:00 UTC restarts the service, which triggers the
startup wipe. Any uploaded case from the working day is gone after that —
this is intentional, not a bug.

---

## 📦 Repository layout

```
DeepTrace/
├── bootstrap.sh             # one-shot installer (Debian / Ubuntu)
├── deeptrace.service        # systemd unit template (consumed by bootstrap)
├── README.md
├── backend/
│   ├── app/                 # FastAPI app
│   │   ├── main.py
│   │   ├── case_manager.py
│   │   ├── llm_service.py
│   │   ├── llm_config.py
│   │   ├── llm_providers/   # OpenAI / Anthropic / Google adapters
│   │   ├── admin/           # /admin/llm router (Basic Auth)
│   │   ├── admin_static/    # llm.html
│   │   ├── chat/            # follow-up Q&A endpoint
│   │   ├── correlation/     # cross-plane alignment
│   │   ├── groundhog/       # radio-trace ingest + anonymise + summary
│   │   ├── imstrace/        # Huawei .zip + .ptmf ingest
│   │   ├── radio_rca/       # deterministic radio detectors
│   │   ├── ran/             # PCAP-side RAN signaling
│   │   └── report.py        # /report/<case_id> HTML renderer
│   ├── analysis/            # voice / IMS / 5G analysers
│   ├── analytics/           # subscriber tracker, KPI engine, trend detector
│   ├── decode/              # TShark field packs, cause maps, vendor codes
│   ├── scripts/             # hash_admin_password.py
│   ├── requirements.txt
│   └── .env.example
└── frontend/                # React 18 SPA
    └── src/
        ├── App.js           # landing + case lifecycle
        ├── Dashboard.js     # tabs + charts
        ├── FlowDiagram.js   # swim-lane view
        └── MermaidDiagram.js
```

---

## ⚠️ Limitations & known gaps

- **PTMF parser** decodes the SIP and log payloads in Huawei NE traces but
  leaves ~12 % of records (Diameter / H.248 binary) classified as "other".
  More decoders can be added; not currently a priority since the SIP +
  warning-log signal already drives a useful RCA.
- **Huawei `.ptmf` is one-sided** — only the originating NE's view is in
  the file, so peer IPs are inferred from SIP Via/Route headers rather
  than from an explicit topology map.
- **Diameter dissection** in the Scapy path is disabled (`Diameter support not available`); TShark handles the full decode for both classification and field extraction.

---

## 📄 License & contact

Released under the [MIT License](LICENSE).

Open an issue on the GitHub repo for bugs or feature requests.
