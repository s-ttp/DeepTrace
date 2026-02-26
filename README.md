# DeepTrace - Intelligent Mobile Network Analysis

DeepTrace is a comprehensive tool for analyzing mobile network traffic (2G, 3G, 4G LTE, 5G SA) from PCAP files. It combines deep packet inspection (DPI) with AI-driven Root Cause Analysis (RCA) to diagnose network failures, voice quality issues, and performance bottlenecks.

## 🏗️ High-Level Architecture

The application follows a modern, decoupled architecture:

*   **Frontend**: React 18 application for interactive visualization (Charts, Sequence Diagrams, Tables).
*   **Backend**: FastAPI (Python) server handling async analysis tasks.
*   **Deep Packet Inspection**: Integrates **TShark** (Wireshark) for detailed field extraction and **Scapy** for lightweight packet parsing.
*   **AI Engine**: Integrates with LLMs (OpenAI GPT / Moonshot Kimi) to provide semantic understanding of network failures.

## 🚀 Key Features

### Data Analysis (2G - 5G)
*   **Multi-Protocol Support**:
    *   **5G SA**: NGAP (N2), PFCP (N4), HTTP/2 (SBI), NAS-5GS.
    *   **4G LTE**: S1-AP, GTP-v2, GTP-U, Diameter (Gx, Gy, S6a).
    *   **Legacy**: 2G/3G SS7 over IP (M3UA, SUA).
*   **Flow tracking**: Aggregates packets into 5-tuple flows with bandwidth and PPS calculation.
*   **Session Correlation**: Automatically links Control Plane sessions (Signaling) with User Plane flows (Data) using TEID/IP correlation.

### 📻 Radio Trace Integration (Groundhog/CovMo)
*   **Multi-Format Ingestion**: Parses HTML, CSV, XLS, XLSX, JSON, and XML Groundhog traces.
*   **Radio KPI Extraction**: Extracts critical RF metrics including RSRP, RSRQ, SINR, CQI, and BLER.
*   **Cross-Plane Correlation**: Aligns UE-side radio events (handovers, RLF) with core network signaling (S1AP/NGAP) using precise timing and cell identity synchronization.
*   **Deterministic Radio Root Causes**: Flags issues like RRC Reconfiguration Latency, Abnormal Radio Releases, E-RAB Setup Failures, and SgNB Addition Failures based on strict protocol evidence.

### Voice & IMS Analysis
*   **Call Reconstruction**: Builds full SIP call lifecycles (Invite -> Bye) including forking and re-invites.
*   **Media Quality (RTP)**:
    *   **Jitter Analysis**: Calculates mean jitter using RFC 3550 standard (`>50ms` warning).
    *   **Packet Loss**: Detects sequence number gaps (`>2%` critical).
    *   **MOS Estimation**: Estimates Mean Opinion Score using the E-Model (ITU-T G.107).
*   **Advanced Detection**:
    *   **One-Way Audio**: Identifies calls with unidirectional media flow.
    *   **Silent Calls**: Detects established calls with extremely low packet rates (<10pps).
    *   **SRVCC**: Correlates SIP INFO messages with S1-AP HandoverRequired for Single Radio Voice Call Continuity analysis.

### 🤖 AI-Driven Root Cause Analysis
*   **Contextual Analysis**: Aggregates signaling errors, data throughput issues, and vendor-specific codes (e.g., Nokia/Huawei/Ericsson).
*   **Confidence Scoring**: Assigns High/Medium/Low confidence to diagnoses based on evidence strength.
*   **Pattern Matching**: Deterministic matching of known 3GPP release causes combined with probabilistic LLM reasoning.

## 📊 Key Performance Indicators (KPIs)

| Category | KPI | description |
|----------|-----|-------------|
| **Voice** | **Jitter** | Variation in packet arrival time (Target: <30ms) |
| **Voice** | **Packet Loss** | Percentage of missing RTP packets (Target: <1%) |
| **Voice** | **MOS-LQE** | Estimated call quality score (1-5 scale) |
| **Signaling** | **Setup Success Rate** | % of attempts resulting in active sessions |
| **Signaling** | **Post-Dial Delay** | Time from INVITE to 180 Ringing |
| **Data** | **Retransmission Rate** | % of TCP retransmissions (Congestion indicator) |

## 🛠️ Setup & Installation

### Prerequisites
*   Node.js (v16+)
*   Python 3.11+
*   `tshark` (Wireshark command line tool) installed and in PATH.

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/s-ttp/DeepTrace.git
    cd DeepTrace
    ```

### Quick Start (Linux/Production)

You can use the included deployment script to build the frontend, set up the backend environment, and install the systemd service automatically:

```bash
chmod +x deploy.sh
./deploy.sh
```

### Manual Installation

1.  **Backend Setup**
    ```bash
    cd backend
    python -m venv venv
    source venv/bin/activate  # or venv\Scripts\activate on Windows
    pip install -r requirements.txt
    ```
    *Create a `.env` file in `backend/` with your API keys (see `.env.example`).*

3.  **Frontend Setup**
    ```bash
    cd ../frontend
    npm install
    npm run build
    ```

### Running the Application (Production)

To start the backend (which also serves the built frontend):

```bash
# From project root
./backend/venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
Access the dashboard at `http://localhost:8000`.
