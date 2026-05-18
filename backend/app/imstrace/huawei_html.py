"""Huawei IMS HTML trace parser.

Input shape (from Huawei IMS / CSCF tracing tool export):
  <bundle>/
    index.html
    index.files/
      message_Data.js          # XML message list (window.message_xmlDoc = '...')
      message_diagram_Data.js  # IP -> NE name/type map
      tree<N>.txt              # parsed text of message N (SIP/Diameter)
      ...

Output: a list of transactions (one dict per signalling message) in the same
shape the rest of the DeepTrace pipeline consumes — so the existing Diameter,
voice/IMS, subscriber-tracker, and LLM analysers all work as-is.

Privacy: subscriber identifiers (IMSI, MSISDN, E.164 phone numbers, tel-uri
phone-context numbers, Authorization usernames) are pseudonymised at the
parser boundary via the same helper used elsewhere in the project, so they
never reach disk, API responses, or the LLM in raw form.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Per-process pseudonym key. Rotates on restart, same posture as
# backend/app/groundhog/anonymise.py.
_SECRET = secrets.token_bytes(32)


def _pseudonym(kind: str, value: str) -> str:
    if not value:
        return value
    digest = hmac.new(_SECRET, f"{kind}|{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{kind.upper()}_{digest[:8]}"


# Patterns, applied in order. Each catches a specific identifier shape.
# IMSI: any standalone 14-15 digit run not inside a longer digit sequence.
_RX_IMSI = re.compile(r"(?<![0-9])(\d{14,15})(?![0-9])")
# E.164 phone numbers with explicit + prefix anywhere.
_RX_E164_PLUS = re.compile(r"\+(\d{8,15})")
# Subscriber digits after a SIP/tel URI prefix — including IMS short codes
# inside `tel:NNNN;phone-context=...`. Caught before the explicit E.164 rule
# because phone-context numbers don't carry a leading "+".
_RX_URI_USER = re.compile(r"(sip:|sips:|tel:|aor=|aor:)\+?(\d{6,15})")
# Authorization / WWW-Authenticate username= "..."
_RX_AUTH_USER = re.compile(r'(username\s*=\s*")([^"]+)(")')


def _redact_identifiers(text: str) -> str:
    """Pseudonymise anything that looks like a subscriber identifier.

    Catches IMSIs (14-15 digits), E.164 numbers (+...), URI-embedded numbers
    (sip:/sips:/tel:), and Authorization usernames. The same input always
    maps to the same pseudonym within a process so call/dialog correlation
    still works.
    """
    if not text or not isinstance(text, str):
        return text

    # 1. IMSI (run first so 15-digit IMSIs aren't grabbed by the E.164 rule)
    text = _RX_IMSI.sub(lambda m: _pseudonym("IMSI", m.group(1)), text)

    # 2. URI-embedded subscriber numbers (tel:, sip:, sips:)
    def _uri(m: re.Match) -> str:
        prefix, digits = m.group(1), m.group(2)
        return f"{prefix}{_pseudonym('MSISDN', digits)}"

    text = _RX_URI_USER.sub(_uri, text)

    # 3. Authorization username — may be IMSI@realm or plain user
    def _auth(m: re.Match) -> str:
        user = m.group(2)
        if "@" in user:
            local, _, realm = user.partition("@")
            if local.isdigit() and 8 <= len(local) <= 16:
                return f'{m.group(1)}{_pseudonym("IMSI", local)}@{realm}{m.group(3)}'
        elif user.isdigit() and 8 <= len(user) <= 16:
            return f'{m.group(1)}{_pseudonym("IMSI", user)}{m.group(3)}'
        return m.group(0)

    text = _RX_AUTH_USER.sub(_auth, text)

    # 4. E.164 numbers with explicit + (digits possibly separated by - or space)
    def _e164(m: re.Match) -> str:
        digits = re.sub(r"[^0-9]", "", m.group(0))
        if len(digits) < 8:
            return m.group(0)
        return _pseudonym("MSISDN", digits)

    text = re.sub(r"\+[\d \-]{8,18}", _e164, text)

    # 5. Final safety net for long bare digit runs (12-19 digits) that slipped
    # through — e.g. TCAP/MAP `calledPartyNumber` fields where Huawei serialises
    # the number as `---- 9749004555757820`. Word-boundary anchored so port
    # numbers and short IDs are untouched.
    text = re.sub(r"(?<![\d])(\d{12,19})(?![\d])",
                  lambda m: _pseudonym("MSISDN", m.group(1)), text)

    return text


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_huawei_zip(file_path: str) -> bool:
    """Return True if the ZIP looks like a Huawei IMS trace bundle."""
    try:
        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    has_message_data = any(n.endswith("/message_Data.js") or n.endswith("message_Data.js") for n in names)
    has_index_files = any("/index.files/" in n for n in names)
    return has_message_data and has_index_files


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_RX_JS_XMLDOC = re.compile(r"window\.\w+_xmlDoc\s*=\s*'(.*)';?\s*$", re.DOTALL)
_RX_JS_UNESCAPE = [
    ("\\'", "'"),
    ("\\\\", "\\"),
    ('\\"', '"'),
    ("\\n", "\n"),
    ("\\r", "\r"),
    ("\\t", "\t"),
]


def _strip_js_wrapper(text: str) -> str:
    m = _RX_JS_XMLDOC.search(text.strip())
    if not m:
        # Some exports use double quotes instead
        m = re.search(r'window\.\w+_xmlDoc\s*=\s*"(.*)";?\s*$', text.strip(), re.DOTALL)
        if not m:
            raise ValueError("Could not locate XML payload in JS file")
    payload = m.group(1)
    for esc, repl in _RX_JS_UNESCAPE:
        payload = payload.replace(esc, repl)
    return payload


def _parse_xml_doc(js_path: Path) -> ET.Element:
    raw = js_path.read_text(encoding="utf-8", errors="replace")
    xml_text = _strip_js_wrapper(raw)
    # Some entries contain stray characters; ElementTree tolerates most.
    return ET.fromstring(xml_text)


def _parse_node_map(diagram_js_path: Path) -> Dict[str, Dict[str, str]]:
    """Build IP → {ne_name, ne_type, ne_fdn} from message_diagram_Data.js."""
    out: Dict[str, Dict[str, str]] = {}
    if not diagram_js_path.exists():
        return out
    try:
        root = _parse_xml_doc(diagram_js_path)
    except Exception as e:
        logger.warning("Could not parse diagram JS: %s", e)
        return out
    for dev in root.iter("DevDATA"):
        ips = (dev.findtext("IP") or "").split(",")
        ne_name = dev.findtext("NeName") or ""
        ne_type = dev.findtext("NeType") or ""
        ne_fdn = dev.findtext("NeFdn") or ""
        for ip in ips:
            ip = ip.strip()
            if ip:
                out[ip] = {"ne_name": ne_name, "ne_type": ne_type, "ne_fdn": ne_fdn}
    return out


def _split_ipport(text: str) -> Tuple[Optional[str], Optional[int]]:
    """Accept 'ip port' or 'ip:port' (also IPv6 in brackets)."""
    if not text:
        return None, None
    text = text.strip()
    # IPv6 like "2001:1a10:...:5699 50691"
    parts = text.rsplit(" ", 1)
    if len(parts) == 2:
        try:
            return parts[0].strip(), int(parts[1])
        except ValueError:
            return parts[0].strip(), None
    if ":" in text and not text.count(":") > 2:
        ip, _, port = text.rpartition(":")
        try:
            return ip, int(port)
        except ValueError:
            return text, None
    return text, None


def _epoch(time_str: str) -> Optional[float]:
    """Convert '2026-03-22 17:01:59.762' to epoch seconds."""
    if not time_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(time_str.strip(), fmt).timestamp()
        except ValueError:
            continue
    return None


def _classify_protocol(message_type: str, interface_type: str) -> str:
    iface = (interface_type or "").upper()
    mt = (message_type or "").upper()
    if "DIAM" in iface or mt in {"UAR", "UAA", "SAR", "SAA", "MAR", "MAA", "AIR", "AIA",
                                 "ULR", "ULA", "CCR", "CCA", "AAR", "AAA", "STR", "STA",
                                 "RTR", "RTA", "PPR", "PPA", "LIR", "LIA", "RAR", "RAA"}:
        return "Diameter"
    if "SIPC" in iface or "SIP" in iface or mt.startswith(("SIP", "1", "2", "3", "4", "5", "6")) \
       or mt in {"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "UPDATE",
                 "INFO", "REFER", "NOTIFY", "MESSAGE", "SUBSCRIBE", "PUBLISH"}:
        return "SIP"
    if "GTP" in iface:
        return "GTP"
    if "S1AP" in iface:
        return "S1AP"
    if "NGAP" in iface:
        return "NGAP"
    return mt or iface or "Unknown"


def _infer_node_roles(transactions: List[Dict[str, Any]], node_map: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Derive functional role names for IPs that the Huawei diagram didn't label.

    Walks every transaction once and votes on each unknown IP based on the
    interfaces it appears on and the message types it carries. Output is a
    stable ``{ip -> friendly-label}`` mapping with sequential numbering when
    a role has multiple instances (e.g. "HSS-1", "HSS-2").
    """
    # Collect, per unknown IP, all (interface_type, message_type) signatures.
    sig_by_ip: Dict[str, List[Tuple[str, str]]] = {}
    for tx in transactions:
        for side in ("src_ip", "dst_ip"):
            ip = tx.get(side)
            if not ip:
                continue
            # Already named in the Huawei diagram → skip
            if node_map.get(ip, {}).get("ne_name"):
                continue
            sig_by_ip.setdefault(ip, []).append(
                (str(tx.get("interface_type") or "").upper(), str(tx.get("message_type") or "").upper())
            )

    def _role_for(ifaces: List[Tuple[str, str]]) -> str:
        # Tally each candidate role across all of the IP's signatures; the
        # dominant role wins. SS7-internal placeholders (0.0.0.0,
        # 254.254.254.254) touch multiple interfaces and would be mis-bucketed
        # by first-match logic.
        votes: Dict[str, int] = {}
        for iface, msg in ifaces:
            role = None
            if "CXDX" in iface or "ATS_HSS" in iface or "HSS_ATS" in iface:
                role = "HSS"
            elif "TCAP" in iface:
                role = "TCAP Layer"
            elif "MAP" in iface:
                role = "MAP Layer (HLR)"
            elif "M3UA" in iface or "SCCP" in iface:
                role = "SS7 Peer"
            elif "GQ" in iface:
                role = "PCRF"
            elif "ATS_CCF" in iface or "CCF_ATS" in iface or msg in ("ACR", "ACA"):
                role = "CCF"
            elif "H248" in iface or "H.248" in iface:
                role = "MGW"
            elif "TRACE_SIPC" in iface and "TRC_MI_SIPC" not in iface:
                role = "UE"
            elif "TRC_MI_SIPC" in iface:
                role = "Remote IMS Peer"
            if role:
                votes[role] = votes.get(role, 0) + 1
        if not votes:
            return "Unknown Node"
        # Pick the highest-count role; stable tie-break by role name.
        return max(votes.items(), key=lambda kv: (kv[1], -len(kv[0])))[0]

    # Assign roles, deduplicate by appending an index when multiple IPs share a role.
    role_for_ip: Dict[str, str] = {}
    role_counts: Dict[str, int] = {}
    for ip, sigs in sig_by_ip.items():
        role = _role_for(sigs)
        role_counts[role] = role_counts.get(role, 0) + 1

    role_seen: Dict[str, int] = {}
    for ip, sigs in sig_by_ip.items():
        role = _role_for(sigs)
        if role_counts.get(role, 0) > 1:
            role_seen[role] = role_seen.get(role, 0) + 1
            role_for_ip[ip] = f"{role}-{role_seen[role]}"
        else:
            role_for_ip[ip] = role
    return role_for_ip


def _interface_family(interface_type: str) -> str:
    """Map Huawei interface type tokens to a friendly label."""
    iface = (interface_type or "").upper()
    if "CXDX" in iface:
        return "Cx/Dx"
    if "SH" in iface:
        return "Sh"
    if "GX" in iface:
        return "Gx"
    if "RX" in iface:
        return "Rx"
    if "S6A" in iface:
        return "S6a"
    if "SIPC_UP" in iface:
        return "Mw (P-CSCF Up)"
    if "SIPC_DOWN" in iface:
        return "Mw (P-CSCF Down)"
    if "ISC" in iface:
        return "ISC"
    if "DIAM" in iface:
        return "Diameter (other)"
    return interface_type or "Unknown"


# Lightweight tree<N>.txt parser. Headers come one per line as "    |_Header: value".
_RX_TREE_LINE = re.compile(r"^\s*\|_(?P<name>[^:]+?):\s*(?P<value>.*?)\s*$")
_RX_TREE_FIRST = re.compile(r"^\s*\|_(?P<line>.+?)\s*$")
_RX_SIP_REQ = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+SIP/2\.0\s*$")
_RX_SIP_STATUS = re.compile(r"^SIP/2\.0\s+(?P<code>\d{3})\s+(?P<reason>.*)$")
_RX_FROM_USER = re.compile(r"<\s*(?:sip|sips|tel):([^@>;]+)")
_RX_CALL_ID = re.compile(r"^([^@]+)", re.IGNORECASE)


def _parse_tree_text(text: str) -> Dict[str, Any]:
    """Extract SIP-style headers (and a few protocol-specific fields) from a tree*.txt."""
    out: Dict[str, Any] = {}
    if not text:
        return out
    # Tree files start with "-Parse Result" then the message lines.
    lines = []
    for raw in text.splitlines():
        m = _RX_TREE_LINE.match(raw)
        if m:
            lines.append((m.group("name").strip(), m.group("value")))
        else:
            m2 = _RX_TREE_FIRST.match(raw)
            if m2:
                lines.append(("__start__", m2.group("line")))

    for name, value in lines:
        if name == "__start__":
            req = _RX_SIP_REQ.match(value)
            sts = _RX_SIP_STATUS.match(value)
            if req:
                out["sip.Method"] = req.group("method")
                out["sip.request_uri"] = req.group("uri")
            elif sts:
                out["sip.Status-Code"] = int(sts.group("code"))
                out["sip.Reason"] = sts.group("reason")
            else:
                out.setdefault("first_line", value)
            continue
        out[f"sip.{name}"] = value

    # Convenience extracts used elsewhere in the codebase
    if "sip.From" in out:
        m = _RX_FROM_USER.search(out["sip.From"])
        if m:
            out["sip.from.user"] = m.group(1)
    if "sip.To" in out:
        m = _RX_FROM_USER.search(out["sip.To"])
        if m:
            out["sip.to.user"] = m.group(1)
    if "sip.Call-ID" in out:
        out["sip.Call-ID"] = (out["sip.Call-ID"] or "").strip()

    # Extract CSeq method (e.g. "21 REGISTER") → procedure name
    cseq = out.get("sip.CSeq") or ""
    parts = cseq.split()
    if len(parts) == 2 and parts[1].isalpha():
        out["procedure"] = parts[1]

    return out


_TCAP_FAILURE_TOKENS = ("ERROR_IND", "U_ABORT_IND", "P_ABORT_IND", "REJECT_IND")


def _success_or_failure(tx: Dict[str, Any], protocol: str) -> str:
    if protocol == "SIP":
        code = tx.get("sip.Status-Code")
        if isinstance(code, int):
            return "failure" if code >= 400 else "success"
    if protocol == "Diameter":
        code = tx.get("diameter.Result-Code") or tx.get("diameter.Experimental-Result-Code")
        try:
            if code is not None and int(code) >= 3000:
                return "failure"
            if code is not None:
                return "success"
        except (TypeError, ValueError):
            return ""
    # MAP / TCAP signalling errors. Huawei's MessageType names them explicitly.
    msg = (tx.get("message_type") or "").upper()
    if any(tok in msg for tok in _TCAP_FAILURE_TOKENS):
        return "failure"
    return ""


def _strip_hex_prefix(s: str) -> str:
    # Some hex values come in as '01' '00' ... — keep only hex digits
    return re.sub(r"[^0-9A-Fa-f]", "", s)


def _parse_diameter_body(hex_text: str) -> Dict[str, Any]:
    """Best-effort Diameter header decode from the hex MessageBody.

    The first 20 bytes of a Diameter message contain version, length, flags,
    command code (3 bytes), application-id (4 bytes), hop-by-hop and end-to-end
    IDs. Result-Code AVP (code 268) lives somewhere in the AVP stream — we
    don't fully parse AVPs here, but extract enough to make the upstream
    Diameter analyser useful.
    """
    out: Dict[str, Any] = {}
    h = _strip_hex_prefix(hex_text or "")
    if len(h) < 40:
        return out
    try:
        cmd_code = int(h[10:16], 16)  # bytes 5..7
        app_id = int(h[16:24], 16)    # bytes 8..11
        out["diameter.cmd.code"] = cmd_code
        out["diameter.applicationId"] = app_id
    except ValueError:
        pass
    # Scan for AVP code 268 (Result-Code) — minimum AVP header is 8 bytes,
    # then 4-byte data. Pattern: 00 00 01 0C ?? ?? ?? ?? <4 bytes data>
    needle = "0000010c"
    pos = h.lower().find(needle)
    if pos >= 0 and pos + 24 <= len(h):
        try:
            data_hex = h[pos + 16:pos + 24]
            out["diameter.Result-Code"] = int(data_hex, 16)
        except ValueError:
            pass
    # Experimental-Result-Code (code 297 = 0x129): grouped AVP with
    # Vendor-Id + Experimental-Result-Code (298 = 0x12A). We scan loosely.
    exp_needle = "0000012a"
    epos = h.lower().find(exp_needle)
    if epos >= 0 and epos + 24 <= len(h):
        try:
            data_hex = h[epos + 16:epos + 24]
            out["diameter.Experimental-Result-Code"] = int(data_hex, 16)
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def ingest_huawei_ims(file_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Parse a Huawei IMS trace bundle (a .zip or a directory) into transactions.

    Returns a dict with:
      - transactions: list of transaction dicts (PCAP-equivalent shape)
      - summary: high-level stats
      - node_map: IP -> {ne_name, ne_type}
    If ``output_dir`` is provided, writes the same data to disk for the case.
    """
    src = Path(file_path)
    if not src.exists():
        raise FileNotFoundError(file_path)

    cleanup_dir: Optional[Path] = None
    if src.is_file() and src.suffix.lower() == ".zip":
        # Extract into a temp dir under output_dir (or a sibling tmp) so the
        # daily wipe cleans it up alongside the case.
        extract_to = Path(output_dir) / "extracted" if output_dir else src.parent / f"_extracted_{src.stem}"
        if extract_to.exists():
            shutil.rmtree(extract_to)
        extract_to.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(src) as z:
            z.extractall(extract_to)
        bundle = extract_to
        if not output_dir:
            cleanup_dir = extract_to
    else:
        bundle = src

    # Locate index.files dir
    candidates = list(bundle.rglob("index.files"))
    if not candidates:
        raise ValueError("Could not find 'index.files' directory in the Huawei trace bundle")
    idx_dir = candidates[0]
    msg_js = idx_dir / "message_Data.js"
    diag_js = idx_dir / "message_diagram_Data.js"
    if not msg_js.exists():
        raise ValueError(f"Missing {msg_js}")

    node_map = _parse_node_map(diag_js)
    logger.info("Huawei IMS: loaded %d NE entries from diagram", len(node_map))

    root = _parse_xml_doc(msg_js)
    data_elements = root.findall("DATA")
    logger.info("Huawei IMS: parsing %d message entries", len(data_elements))

    transactions: List[Dict[str, Any]] = []
    interface_counts: Dict[str, int] = {}
    call_ids: set = set()
    message_types: Dict[str, int] = {}

    for el in data_elements:
        tr_id = el.findtext("trID") or ""
        time_str = el.findtext("Time") or ""
        ts = _epoch(time_str)
        message_type = (el.findtext("MessageType") or "").strip()
        interface_type = (el.findtext("InterfaceType") or "").strip()
        dev_type = (el.findtext("DevType") or "").strip()
        ne_pair = (el.findtext("NeName") or "").strip()
        call_id = _redact_identifiers((el.findtext("callidBody") or "").strip())
        body_hex = (el.findtext("MessageBody") or "").strip()

        sender_el = el.find("Sender")
        receiver_el = el.find("Receiver")
        s_ip, s_port = _split_ipport(sender_el.text if sender_el is not None else "")
        r_ip, r_port = _split_ipport(receiver_el.text if receiver_el is not None else "")

        # Load the parsed message body if available
        particular = el.find("Particular")
        parsed = {}
        if particular is not None:
            fname = particular.attrib.get("file", "")
            if fname:
                tree_path = idx_dir / fname
                if tree_path.exists():
                    try:
                        text = tree_path.read_text(encoding="utf-8", errors="replace")
                        text = _redact_identifiers(text)
                        parsed = _parse_tree_text(text)
                    except Exception as e:
                        logger.debug("Could not parse %s: %s", fname, e)

        protocol = _classify_protocol(message_type, interface_type)
        tx: Dict[str, Any] = {
            "tr_id": tr_id,
            "time_epoch": ts,
            "time_text": time_str,
            "protocol": protocol,
            "message_type": message_type,
            "interface_type": interface_type,
            "interface_family": _interface_family(interface_type),
            "dev_type": dev_type,
            "ne_pair": ne_pair,
            "src_ip": s_ip,
            "src_port": s_port,
            "dst_ip": r_ip,
            "dst_port": r_port,
            "src_ne": (node_map.get(s_ip) or {}).get("ne_name"),
            "dst_ne": (node_map.get(r_ip) or {}).get("ne_name"),
            "src_ne_type": (node_map.get(s_ip) or {}).get("ne_type"),
            "dst_ne_type": (node_map.get(r_ip) or {}).get("ne_type"),
            "call_id": call_id,
            "session_ids": {"call_id": call_id} if call_id else {},
            "timestamp": ts,
        }
        # Merge parsed-text fields (SIP headers, etc.)
        if parsed:
            tx.update(parsed)

        # Diameter best-effort
        if protocol == "Diameter":
            tx.update(_parse_diameter_body(body_hex))

        # Convenience: existing analysers consume sip.Call-ID and procedure;
        # plus we keep status (success/failure) for trend_detector.
        if protocol == "SIP" and call_id and not tx.get("sip.Call-ID"):
            tx["sip.Call-ID"] = call_id
        if not tx.get("procedure"):
            tx["procedure"] = message_type
        tx["status"] = _success_or_failure(tx, protocol)

        # Pseudonymise From/To user fields (E.164 / IMSI shapes) — they're
        # already pseudonymised in the parsed text but the convenience fields
        # were extracted before redaction in some paths.
        for k in ("sip.from.user", "sip.to.user"):
            v = tx.get(k)
            if v:
                tx[k] = _redact_identifiers(v)

        transactions.append(tx)
        if call_id:
            call_ids.add(call_id)
        interface_counts[interface_type or "(none)"] = interface_counts.get(interface_type or "(none)", 0) + 1
        message_types[message_type or "(none)"] = message_types.get(message_type or "(none)", 0) + 1

    # Second pass: infer functional roles for IPs the Huawei diagram left
    # unlabeled (UE, HSS instances, PCRF, CCF, MGW, remote IMS, SS7 layers)
    # and write them back into every transaction so the swim-lane diagram
    # and message_sequence never show raw IPs.
    role_for_ip = _infer_node_roles(transactions, node_map)
    if role_for_ip:
        for tx in transactions:
            for ip_key, ne_key in (("src_ip", "src_ne"), ("dst_ip", "dst_ne")):
                if not tx.get(ne_key) and tx.get(ip_key) in role_for_ip:
                    tx[ne_key] = role_for_ip[tx[ip_key]]

    # Build summary
    epochs = [t["time_epoch"] for t in transactions if t.get("time_epoch")]
    summary = {
        "total_messages": len(transactions),
        "unique_call_ids": len(call_ids),
        "time_range": {
            "start_epoch": min(epochs) if epochs else None,
            "end_epoch": max(epochs) if epochs else None,
            "duration_seconds": (max(epochs) - min(epochs)) if len(epochs) >= 2 else 0,
        },
        "message_type_counts": dict(sorted(message_types.items(), key=lambda kv: -kv[1])[:25]),
        "interface_counts": dict(sorted(interface_counts.items(), key=lambda kv: -kv[1])[:20]),
        "node_types_observed": sorted({n["ne_type"] for n in node_map.values() if n.get("ne_type")})[:25],
        "node_count": len({n["ne_name"] for n in node_map.values() if n.get("ne_name")}),
    }

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        with (out / "transactions.json").open("w") as f:
            json.dump(transactions, f, default=str)
        with (out / "summary.json").open("w") as f:
            json.dump(summary, f, indent=2, default=str)
        # node_map keys are IPs; harmless to persist (not subscriber data).
        with (out / "node_map.json").open("w") as f:
            json.dump(node_map, f, indent=2)
        logger.info("Huawei IMS: wrote artifacts to %s", out)

    # Clean temp extract dir if we created one outside the case dir
    if cleanup_dir and cleanup_dir.exists() and not output_dir:
        try:
            shutil.rmtree(cleanup_dir)
        except Exception:
            pass

    return {"transactions": transactions, "summary": summary, "node_map": node_map}


def build_message_sequence(transactions: List[Dict[str, Any]], max_messages: int = 50) -> List[Dict[str, Any]]:
    """Emit a FlowDiagram-shaped message list from Huawei transactions.

    Prioritises failures and their surrounding context so the swim-lane view
    actually shows the problem instead of the first N happy-path REGISTERs.
    """
    items = [t for t in transactions if t.get("time_epoch") is not None]
    items.sort(key=lambda t: t["time_epoch"])

    # Find failure indices, then expand a small window around each so context survives
    failure_idx = [i for i, t in enumerate(items) if str(t.get("status", "")).lower() == "failure"]
    keep = set()
    if failure_idx and len(items) > max_messages:
        for i in failure_idx:
            lo, hi = max(0, i - 4), min(len(items), i + 6)
            for j in range(lo, hi):
                keep.add(j)
        # Pad with earliest few messages for orientation
        for j in range(min(8, len(items))):
            keep.add(j)
        # Trim to max_messages from the union, preserving order
        ordered = sorted(keep)[:max_messages]
        items = [items[j] for j in ordered]
    else:
        items = items[:max_messages]

    out: List[Dict[str, Any]] = []
    for tx in items:
        method = tx.get("sip.Method") or ""
        status = tx.get("sip.Status-Code")
        proto = tx.get("protocol", "")
        if proto == "SIP":
            info = (f"SIP {method}" if method
                    else (f"SIP {status} {tx.get('sip.Reason', '')}" if status
                          else f"SIP {tx.get('message_type', '')}"))
        elif proto == "Diameter":
            info = f"Diameter {tx.get('message_type', '')} ({tx.get('interface_family', '')})"
        else:
            info = f"{proto} {tx.get('message_type', '')}".strip()
        out.append({
            "timestamp": tx.get("time_epoch") or 0,
            "src_ip": tx.get("src_ip") or "",
            "dst_ip": tx.get("dst_ip") or "",
            "src_port": tx.get("src_port") or 0,
            "dst_port": tx.get("dst_port") or 0,
            "protocol": proto,
            "transport": "SCTP" if "SCTP" in (tx.get("sip.Via") or "") else "TCP",
            "length": 0,
            "info": info,
            "src_name": tx.get("src_ne") or tx.get("src_ip") or "?",
            "dst_name": tx.get("dst_ne") or tx.get("dst_ip") or "?",
            "sip_method": method or "",
            "sip_status": status or "",
            "diameter_cmd": tx.get("message_type", "") if proto == "Diameter" else "",
        })
    return out


def _mermaid_safe_id(name: str, seen: Dict[str, str]) -> str:
    """Produce a stable Mermaid participant id for ``name`` (registered once)."""
    if name in seen:
        return seen[name]
    pid = f"p{len(seen)}"
    seen[name] = pid
    return pid


def _mermaid_message_text(it: Dict[str, Any]) -> str:
    """Build a Mermaid arrow label from a FlowDiagram-shaped message dict."""
    proto = it.get("protocol", "")
    method = it.get("sip_method") or ""
    status = it.get("sip_status")
    if proto == "SIP":
        if method:
            return f"SIP {method}"
        if isinstance(status, int) and status:
            return f"SIP {status}".strip()
        return it.get("info", "SIP")
    if proto == "Diameter":
        return it.get("info", "Diameter")
    return it.get("info", proto)


def build_mermaid_from_sequence(items: List[Dict[str, Any]], max_steps: int = 30) -> str:
    """Generate a Mermaid sequenceDiagram from a FlowDiagram-shaped message list.

    Works for both Huawei IMS transactions (via build_message_sequence) and
    raw PCAP-derived message_sequence from telecom_analyzer.extract_message_sequence.
    """
    if not items:
        return ""
    if len(items) > max_steps:
        items = items[:max_steps]

    # 401/407 are auth challenges in IMS REGISTER (normal AKA round-trip), not
    # real failures. Show them as solid arrows annotated as challenges.
    _AUTH_CHALLENGE = {401, 407}

    participants: Dict[str, str] = {}
    body: List[str] = []
    for it in items:
        src = it.get("src_name") or it.get("src_ip") or "?"
        dst = it.get("dst_name") or it.get("dst_ip") or "?"
        src_pid = _mermaid_safe_id(str(src), participants)
        dst_pid = _mermaid_safe_id(str(dst), participants)
        msg = _mermaid_message_text(it).replace(":", " ").replace("\n", " ")
        status = it.get("sip_status")
        # Status sometimes comes back as a string; coerce when looking at it.
        try:
            status_i = int(status) if status not in (None, "") else None
        except (TypeError, ValueError):
            status_i = None
        info_lower = (it.get("info") or "").lower()
        tcap_error = "error_ind" in info_lower or "abort_ind" in info_lower
        is_challenge = status_i is not None and status_i in _AUTH_CHALLENGE
        is_failure = (
            (status_i is not None and status_i >= 400 and not is_challenge)
            or tcap_error
        )
        arrow = "-x" if is_failure else "->>"
        suffix = " (challenge)" if is_challenge else ""
        body.append(f"  {src_pid} {arrow} {dst_pid}: {msg[:80]}{suffix}")
        if is_failure:
            label = f"FAILURE {status_i}" if status_i else "FAILURE"
            body.append(f"  Note over {dst_pid}: {label}")

    # Build the header with participant aliases (id as "Display Name")
    header = ["sequenceDiagram"]
    for name, pid in participants.items():
        clean = name.replace('"', "'").replace("\n", " ")
        header.append(f'  participant {pid} as "{clean}"')

    return "\n".join(header + body)


def build_mermaid_diagram(transactions: List[Dict[str, Any]], max_steps: int = 30) -> str:
    """Huawei-specific wrapper: build the message sequence then the diagram.

    Kept for backward compatibility with imstrace/pipeline.py.
    """
    items = build_message_sequence(transactions, max_messages=max_steps)
    return build_mermaid_from_sequence(items, max_steps=max_steps)


def format_huawei_summary_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("total_messages"):
        return "## HUAWEI IMS TRACE: No Huawei IMS trace uploaded."
    lines = ["## HUAWEI IMS CORE TRACE"]
    lines.append(f"- Total messages: {summary['total_messages']}, unique Call-IDs: {summary['unique_call_ids']}")
    tr = summary.get("time_range", {})
    if tr.get("duration_seconds"):
        lines.append(f"- Duration: {tr['duration_seconds']:.1f}s")
    if summary.get("node_types_observed"):
        lines.append(f"- Node types: {', '.join(summary['node_types_observed'])}")
    if summary.get("interface_counts"):
        top_ifs = list(summary["interface_counts"].items())[:6]
        lines.append("- Top interfaces: " + ", ".join(f"{k}×{v}" for k, v in top_ifs))
    if summary.get("message_type_counts"):
        top_msgs = list(summary["message_type_counts"].items())[:8]
        lines.append("- Top message types: " + ", ".join(f"{k}×{v}" for k, v in top_msgs))
    return "\n".join(lines)
