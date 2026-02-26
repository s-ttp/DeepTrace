from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT

def create_pdf(filename):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = styles['Title']
    heading1_style = styles['Heading1']
    heading2_style = styles['Heading2']
    body_style = styles['BodyText']
    body_style.alignment = TA_JUSTIFY
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['BodyText'],
        bulletIndent=10,
        leftIndent=20,
        spaceAfter=5
    )

    story = []

    # --- Title Page ---
    story.append(Paragraph("NetTrace AI", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Application Documentation & Capabilities", styles['Heading2']))
    story.append(Spacer(1, 36))
    story.append(Paragraph("This document provides an overview of the NetTrace AI application, its high-level architecture, and its comprehensive capabilities for mobile network analysis (Voice & Data).", body_style))
    story.append(PageBreak())

    # --- 2. Packet Processing Workflow (TShark) ---
    story.append(Paragraph("2. Packet Processing Workflow", heading1_style))
    story.append(Paragraph("The system employs a multi-stage decoding strategy involving both Scapy (lightweight) and TShark (Deep Packet Inspection).", body_style))
    
    tshark_bullets = [
        ListItem(Paragraph("<b>Step 1: Ingestion:</b> PCAP files are uploaded and validated.", bullet_style)),
        ListItem(Paragraph("<b>Step 2: Field Extraction (TShark):</b> The <code>decode/tshark.py</code> module runs <code>tshark -T json</code> to extract specific telecom fields (e.g., <code>sip.Call-ID</code>, <code>gtp.teid</code>, <code>ngap.procedureCode</code>). This allows access to deeply nested vendor-specific fields that standard parsers miss.", bullet_style)),
        ListItem(Paragraph("<b>Step 3: Transaction Building:</b> Raw packets are grouped into logical transactions (Request/Response pairs) by <code>decode/transactions_builder.py</code>. This handles retransmissions and helps calculate precise latency.", bullet_style)),
    ]
    story.append(ListFlowable(tshark_bullets, bulletType='bullet'))
    story.append(Spacer(1, 12))

    # --- 3. Analysis Logic ---
    story.append(Paragraph("3. Analysis Logic (Voice & Data)", heading1_style))
    
    story.append(Paragraph("<b>Data Analysis</b>", heading2_style))
    data_bullets = [
        ListItem(Paragraph("<b>Flow Aggregation:</b> Packets are hashed by 5-tuple (Src/Dst IP & Port, Protocol) to create 'Flow' objects.", bullet_style)),
        ListItem(Paragraph("<b>Session Correlation:</b> The engine links independent flows into 'Subscriber Sessions' by matching GTP-TEIDs (Tunnel Endpoint IDs) or IP pairs. This allows correlation of Control Plane (Signaling) with User Plane (Data).", bullet_style)),
    ]
    story.append(ListFlowable(data_bullets, bulletType='bullet'))

    # --- 3. Voice Capabilities (Deep Dive) ---
    story.append(Paragraph("3. Voice & IMS Capabilities (Deep Dive)", heading1_style))
    story.append(Paragraph("The system includes a dedicated Media Plane Analyzer that processes RTP/RTCP streams to detect quality degradation.", body_style))
    
    voice_bullets = [
        ListItem(Paragraph("<b>Call Flow Reconstruction:</b> Builds complete SIP call flows (Invite -> Bye) and correlates them with media streams using SDP port parsing.", bullet_style)),
        ListItem(Paragraph("<b>One-Way Audio Detection:</b> Analyzes bidirectional RTP flow pairs. If a call has Established state but RTP packets flow in only one direction (e.g., UE->Network only), it triggers a 'Critical' finding.", bullet_style)),
        ListItem(Paragraph("<b>Silent Call / Low Activity:</b> Detects established calls where the packet rate is below 10pps (Packets Per Second) for duration > 5s, indicating silence or potential Comfort Noise Generation (CNG) issues.", bullet_style)),
        ListItem(Paragraph("<b>SRVCC/Handover:</b> Detects Single Radio Voice Call Continuity by correlating release causes (SIP 200 OK after INFO) with S1-AP HandoverRequired messages.", bullet_style)),
    ]
    story.append(ListFlowable(voice_bullets, bulletType='bullet'))
    story.append(Spacer(1, 12))

    # --- 4. Quality KPIs & Formulas ---
    story.append(Paragraph("4. Key Performance Indicators & Formulas", heading1_style))
    story.append(Paragraph("Network health is determined by specific telecom KPIs derived from RFC standards.", body_style))
    
    story.append(Paragraph("<b>Voice Quality (RTP)</b>", heading2_style))
    voice_kpi_bullets = [
        ListItem(Paragraph("<b>Jitter (RFC 3550):</b> Calculated as the mean deviation of inter-arrival time. Formula: <code>J(i) = J(i-1) + (|D(i-1, i)| - J(i-1))/16</code>. Threshold: >50ms is Warning.", bullet_style)),
        ListItem(Paragraph("<b>Packet Loss:</b> Detected by sequence number gaps. <br/>Formula: <code>Loss % = (Expected - Received) / Expected * 100</code>. Threshold: >2% is Critical.", bullet_style)),
        ListItem(Paragraph("<b>MOS-LQE (E-Model):</b> Estimated Mean Opinion Score based on ITU-T G.107. <br/>Derivation: <code>R-Factor = 93.2 - Id(Delay) - Ie(Loss)</code>. <br/>Mapping: R < 60 -> MOS < 3.1 (Poor).", bullet_style)),
    ]
    story.append(ListFlowable(voice_kpi_bullets, bulletType='bullet'))

    story.append(Paragraph("<b>Signaling KPIs</b>", heading2_style))
    sig_kpi_bullets = [
        ListItem(Paragraph("<b>Post-Dial Delay (PDD):</b> Time from SIP INVITE to 180 Ringing. Analyzed to detect Core Network latency.", bullet_style)),
        ListItem(Paragraph("<b>Setup Success Rate (SSR):</b> Ratio of sessions reaching 'Active' state vs. total attempts.", bullet_style)),
        ListItem(Paragraph("<b>SIP Retransmissions:</b> Duplicate requests (same Branch ID) within T1 timer (500ms). Indicates packet loss or server overload.", bullet_style)),
    ]
    story.append(ListFlowable(sig_kpi_bullets, bulletType='bullet'))
    story.append(Spacer(1, 12))

    # --- 5. Root Cause Analysis (RCA) ---
    story.append(Paragraph("5. AI-Driven Root Cause Determination", heading1_style))
    story.append(Paragraph("Root Cause Analysis is a multi-step process integrating deterministic rules with Probabilistic AI:", body_style))
    
    rca_bullets = [
        ListItem(Paragraph("<b>Context Gathering:</b> The backend aggregates all Flows, Transaction Failures, Bandwidth Stats, and SIP/GTP Error Codes into a structured context JSON.", bullet_style)),
        ListItem(Paragraph("<b>Pattern Matching (Deterministic):</b> The system first checks for known signatures (e.g., specific Release Causes like 'Radio Link Failure' or 'Network Congestion').", bullet_style)),
        ListItem(Paragraph("<b>LLM Reasoning (Probabilistic):</b> The aggregated context is sent to the LLM. The model analyzes the relationship between signaling failures and data throughput (e.g., 'High retransmissions on GTP-U caused SIP timeout').", bullet_style)),
        ListItem(Paragraph("<b>Confidence Scoring:</b> The AI assigns a confidence score (High/Medium/Low) based on the strength of the evidence (e.g., specific error codes vs. general timeouts).", bullet_style)),
    ]
    story.append(ListFlowable(rca_bullets, bulletType='bullet'))

    # Build
    doc.build(story)
    print(f"PDF generated successfully: {filename}")

if __name__ == "__main__":
    create_pdf("/home/sttp/pcap/temp/NetTraceAI_Documentation.pdf")
