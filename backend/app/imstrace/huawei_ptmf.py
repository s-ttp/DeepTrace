"""Huawei PTMF (Performance Trace Message Format) parser.

PTMF is the Huawei NE-side binary trace format exported by their tracing
tools (User Interface trace dumps from SBC, CSCF, ATS, etc.). The file is a
sequence of 4-byte tag + 4-byte big-endian length + value records.

Top-level tags observed::

    magic = 0xF634F634
    fver / ttyp / fno. / ntyp / nver / lver / colo / info   (header)
    msg0 * N                                                (message records)

Each ``msg0`` record carries a 34-byte fixed header followed by a body that
is one of: a plain-text SIP message, an internal NE log line
(``MID(n) PID(n) Level(...)``), or another binary payload (Diameter / H.248).

We re-use the SIP header parser and the anonymisation helpers from the
existing Huawei HTML path, and emit the same ``transactions`` shape so the
rest of the pipeline (Phase 2 analysers, diagram builders) works unchanged.
"""
from __future__ import annotations

import json
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .huawei_html import (
    _redact_identifiers,
    _parse_tree_text,
    _classify_protocol,
    _interface_family,
    _success_or_failure,
    _parse_diameter_body,
)

logger = logging.getLogger(__name__)

PTMF_MAGIC = b"\xf6\x34\xf6\x34"
# 4 (signed-length tag) + 4 (trace-type) + 8 (seq) + 8 (filler 0xFF)
#   + 12 (date: yyyy yyyy mm dd HH MM SS + 5 bytes subsec/pad/ms)
MSG_HEADER_SIZE = 36

_SIP_METHOD_TOKENS = (b"INVITE ", b"REGISTER ", b"NOTIFY ", b"BYE ", b"ACK ", b"CANCEL ",
                      b"OPTIONS ", b"PRACK ", b"UPDATE ", b"INFO ", b"MESSAGE ", b"REFER ",
                      b"SUBSCRIBE ", b"PUBLISH ")
_SIP_RESPONSE_PREFIX = b"SIP/2.0 "  # response status line
_LOG_LINE_RE = re.compile(rb"MID\(\d+\)\s*PID\(\d+\)\s*Level\([A-Z]+\)\s*->.+", re.DOTALL)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def detect_ptmf(file_path: str) -> bool:
    """Quick magic-byte check."""
    try:
        with open(file_path, "rb") as f:
            return f.read(4) == PTMF_MAGIC
    except OSError:
        return False


# --------------------------------------------------------------------------
# Top-level TLV walk
# --------------------------------------------------------------------------

def _iter_top_tlvs(data: bytes):
    """Yield (tag, length, value, offset) for each TLV after the magic."""
    off = 4
    while off + 8 <= len(data):
        tag = data[off:off + 4]
        try:
            tag_s = tag.decode("ascii")
        except UnicodeDecodeError:
            logger.warning("PTMF: non-ASCII tag at offset %d (0x%s); aborting walk", off, tag.hex())
            return
        length = struct.unpack(">I", data[off + 4:off + 8])[0]
        if length > len(data) - (off + 8):
            logger.warning("PTMF: oversize TLV at offset %d tag=%s len=%d (file %d); aborting",
                           off, tag_s, length, len(data))
            return
        yield tag_s, length, data[off + 8:off + 8 + length], off
        off += 8 + length


def _parse_info_block(value: bytes) -> Dict[str, str]:
    """Header `info` is itself a sequence of 4-byte tag + 4-byte length + value."""
    out: Dict[str, str] = {}
    off = 0
    while off + 8 <= len(value):
        try:
            tag = value[off:off + 4].decode("ascii")
        except UnicodeDecodeError:
            break
        length = struct.unpack(">I", value[off + 4:off + 8])[0]
        if length > len(value) - (off + 8) or length > 1_000_000:
            break
        v = value[off + 8:off + 8 + length]
        try:
            out[tag] = v.rstrip(b"\x00").decode("utf-8", "replace")
        except Exception:
            out[tag] = v.hex()
        off += 8 + length
    return out


# --------------------------------------------------------------------------
# Per-msg0 header
# --------------------------------------------------------------------------

def _parse_msg_header(rec: bytes) -> Dict[str, Any]:
    """Decode the 36-byte fixed header of a ``msg0`` record.

    Layout (byte-by-byte verified against the user's A-SBC trace)::

        offset 0..3   int32 (signed length tag — varies per record)
        offset 4..7   u32   trace_type
        offset 8..9   u16   (zero on this trace)
        offset 10..13 u32   sequence number
        offset 14..19 0xFF * 6 (filler)
        offset 20..21 u16   year
        offset 22     u8    month
        offset 23     u8    day
        offset 24     u8    hour (UTC)
        offset 25     u8    minute
        offset 26     u8    second
        offset 27..29 (sub-second high / module id — not yet decoded)
        offset 30..31 u16   milliseconds
        offset 32..35 (padding / extra header)
    """
    if len(rec) < MSG_HEADER_SIZE:
        return {}
    trace_type = struct.unpack(">I", rec[4:8])[0]
    seq = struct.unpack(">I", rec[10:14])[0]
    year = struct.unpack(">H", rec[20:22])[0]
    month = rec[22]
    day = rec[23]
    hour = rec[24]
    minute = rec[25]
    second = rec[26]
    millis = struct.unpack(">H", rec[30:32])[0]
    if millis > 999:
        millis = 0
    try:
        ts = datetime(year, month, day, hour, minute, second, millis * 1000, tzinfo=timezone.utc)
        epoch = ts.timestamp()
        text = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{millis:03d}"
    except (ValueError, OverflowError):
        epoch, text = None, ""
    return {
        "trace_type": trace_type,
        "seq": seq,
        "time_epoch": epoch,
        "time_text": text,
    }


# --------------------------------------------------------------------------
# Body classification
# --------------------------------------------------------------------------

def _find_sip_message(body: bytes) -> Optional[str]:
    """Return the SIP text inside ``body``, or None if not found.

    Huawei prefixes the SIP request-line with some binary header chrome
    (URI fragments + ports), so we scan for SIP method tokens or the response
    prefix, then trim back to the start of the line.
    """
    lower = body
    # First try response form
    start = -1
    if lower.startswith(b"SIP/2.0 "):
        start = 0
    else:
        for needle in _SIP_METHOD_TOKENS:
            ix = lower.find(needle)
            if ix < 0:
                continue
            # Walk back to start of line (after \n or beginning of body)
            ls = lower.rfind(b"\n", 0, ix)
            ls = ls + 1 if ls >= 0 else 0
            # Sanity: the line at ls must contain " SIP/2.0" (request line)
            line_end = lower.find(b"\r\n", ls)
            if line_end > 0 and b" SIP/2.0" in lower[ls:line_end]:
                start = ls
                break
        else:
            # Maybe a response form embedded mid-body
            ix = lower.find(b"\r\nSIP/2.0 ")
            if ix >= 0:
                start = ix + 2
    if start < 0:
        return None
    # Find the end of the SIP message: blank-line terminator \r\n\r\n, then we
    # keep the body too (SDP / message body) up to first non-text byte.
    end_headers = lower.find(b"\r\n\r\n", start)
    if end_headers < 0:
        # Take until end of record
        text_bytes = lower[start:]
    else:
        # Include body up to first non-printable byte
        end_msg = end_headers + 4
        for j in range(end_msg, min(len(lower), end_msg + 4000)):
            b = lower[j]
            if b < 0x09 or (0x0E <= b < 0x20):
                end_msg = j
                break
        else:
            end_msg = min(len(lower), end_msg + 4000)
        text_bytes = lower[start:end_msg]
    try:
        return text_bytes.decode("utf-8", "replace")
    except Exception:
        return None


def _find_log_line(body: bytes) -> Optional[str]:
    """Extract an internal NE warning line (MID/PID/Level)."""
    m = _LOG_LINE_RE.search(body)
    if not m:
        return None
    # Stop at first non-printable byte
    text = m.group(0)
    end = len(text)
    for i, b in enumerate(text):
        if b < 0x09 or (0x0E <= b < 0x20):
            end = i
            break
    return text[:end].decode("utf-8", "replace").strip()


def _looks_like_diameter(body: bytes) -> bool:
    """Diameter messages start with version byte 0x01 followed by a 3-byte
    length field; AVPs follow. Heuristic check on body[34:] after our header."""
    if len(body) < 20:
        return False
    if body[0] != 0x01:
        return False
    # Length field at bytes 1..3 (big-endian 24-bit) should be <= body length
    length = (body[1] << 16) | (body[2] << 8) | body[3]
    return 20 <= length <= len(body) + 64


# --------------------------------------------------------------------------
# SIP -> transaction
# --------------------------------------------------------------------------

_SIP_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+SIP/2\.0\s*$")
_SIP_STATUS_LINE = re.compile(r"^SIP/2\.0\s+(?P<code>\d{3})\s+(?P<reason>.*)$")
_FROM_USER = re.compile(r"<\s*(?:sip|sips|tel):([^@>;]+)")
# IPv6-in-brackets or IPv4 inside SIP URI / Via host: `[2001:1a10:...]:5060` or `1.2.3.4:5060`
_HOST_IN_URI = re.compile(
    r"(?:sip:|sips:|//|@|\bSIP/2\.0/[A-Z]+\s+)"   # preceded by URI scheme or Via transport
    r"(?:\[(?P<v6>[0-9a-fA-F:]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3}))"
)


def _extract_peer_ip(sip_fields: Dict[str, Any], own_ip: str = "") -> str:
    """Pull the next-hop peer IP out of SIP Via / Route / Contact headers.

    Huawei PTMF is one-sided (NE's view only); the destination of each
    message is implicit. The first ``Via:`` of a request points to the
    sender; the request-URI / Route / Contact points to the receiver.
    Returns "" if no IP could be extracted.
    """
    # Responses go back along the Via chain — the topmost Via is the next hop.
    for header in ("sip.Via", "sip.Route", "sip.Record-Route",
                   "sip.Contact", "sip.request_uri"):
        v = sip_fields.get(header) or ""
        if not v:
            continue
        for m in _HOST_IN_URI.finditer(v):
            ip = m.group("v6") or m.group("v4") or ""
            if ip and ip != own_ip:
                return ip
    return ""


def _sip_text_to_transaction_fields(sip_text: str) -> Dict[str, Any]:
    """Parse a SIP message into a flat dict of fields the rest of the pipeline
    expects: ``sip.Method`` / ``sip.Status-Code`` / ``sip.Call-ID`` / etc.

    Inline parser (does not reuse the .zip tree parser, which mis-handles
    request-lines that contain a colon inside ``sip:URI``).
    """
    out: Dict[str, Any] = {}
    if not sip_text:
        return out
    lines = sip_text.splitlines()
    if not lines:
        return out

    first = lines[0].strip()
    req = _SIP_REQUEST_LINE.match(first)
    sts = _SIP_STATUS_LINE.match(first)
    if req:
        out["sip.Method"] = req.group("method")
        out["sip.request_uri"] = req.group("uri")
    elif sts:
        out["sip.Status-Code"] = int(sts.group("code"))
        out["sip.Reason"] = sts.group("reason").strip()

    for raw in lines[1:]:
        line = raw.rstrip()
        if not line:
            break  # body separator
        if line.startswith((" ", "\t")):
            # SIP header continuation — append to previous if any
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        out[f"sip.{name}"] = value

    # Convenience extracts used by Phase 2 analysers
    if out.get("sip.From"):
        m = _FROM_USER.search(out["sip.From"])
        if m:
            out["sip.from.user"] = m.group(1)
    if out.get("sip.To"):
        m = _FROM_USER.search(out["sip.To"])
        if m:
            out["sip.to.user"] = m.group(1)

    # CSeq method ("21 REGISTER") → procedure (the request type even on responses)
    cseq = out.get("sip.CSeq") or ""
    parts = cseq.split()
    if len(parts) == 2 and parts[1].isalpha():
        out["procedure"] = parts[1]
    elif out.get("sip.Method"):
        out["procedure"] = out["sip.Method"]

    return out


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def ingest_huawei_ptmf(file_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Parse a Huawei PTMF binary trace file into transactions.

    Returns ``{transactions, summary, node_map, log_findings}`` — same shape
    as the .zip ingest, plus a flat list of NE log warnings the LLM RCA can
    use as expert findings.
    """
    src = Path(file_path)
    if not src.exists():
        raise FileNotFoundError(file_path)
    data = src.read_bytes()
    if not data.startswith(PTMF_MAGIC):
        raise ValueError(f"{src.name} is not a Huawei PTMF file (bad magic)")

    header_props: Dict[str, str] = {}
    info_kv: Dict[str, str] = {}
    msg_count_total = 0
    msg_records: List[Tuple[Dict[str, Any], bytes]] = []

    for tag, length, value, _off in _iter_top_tlvs(data):
        if tag == "msg0":
            hdr = _parse_msg_header(value)
            msg_records.append((hdr, value[MSG_HEADER_SIZE:]))
            msg_count_total += 1
        elif tag == "info":
            info_kv = _parse_info_block(value)
        elif tag in ("fver", "ttyp", "fno.", "ntyp", "nver", "lver", "colo"):
            header_props[tag] = value.hex() if not value.isascii() else value.rstrip(b"\x00").decode("utf-8", "replace")

    logger.info("PTMF: top-level walk found %d msg0 records, info=%s",
                msg_count_total, list(info_kv.keys()))

    # Build NE info / node_map from the info TLV. Useful fields seen:
    # mnam (NE name), unam (user), onam (NE class), o-ip (NE IP)
    ne_name = info_kv.get("mnam") or info_kv.get("onam") or ""
    ne_ip = info_kv.get("o-ip") or ""
    ne_class = info_kv.get("onam") or ""
    ne_version = header_props.get("nver") or ""
    node_map: Dict[str, Dict[str, str]] = {}
    if ne_ip:
        node_map[ne_ip] = {"ne_name": ne_name or ne_ip, "ne_type": ne_class, "ne_fdn": ""}

    # Classify each record
    transactions: List[Dict[str, Any]] = []
    log_findings: List[Dict[str, Any]] = []
    sip_count = log_count = diam_count = other_count = 0
    message_types: Dict[str, int] = {}
    interfaces: Dict[str, int] = {}

    for hdr, body in msg_records:
        ts = hdr.get("time_epoch")
        time_text = hdr.get("time_text") or ""
        if not body:
            other_count += 1
            continue

        sip_text = _find_sip_message(body)
        if sip_text:
            redacted = _redact_identifiers(sip_text)
            sip_fields = _sip_text_to_transaction_fields(redacted)
            # Skip fragments where neither a request-line nor a status-line
            # was recognised — these are partial bodies / binary chrome that
            # would otherwise show as "SIP SIP" in the diagram.
            if not sip_fields.get("sip.Method") and not sip_fields.get("sip.Status-Code"):
                other_count += 1
                continue
            message_type = sip_fields.get("sip.Method") or f"{sip_fields['sip.Status-Code']} Response"
            peer_ip = _extract_peer_ip(sip_fields, own_ip=ne_ip)
            # Direction heuristic: requests (have a Method) originate from the
            # peer toward us if the topmost Via host is the peer; responses go
            # the opposite way. We don't try to be perfect — what matters for
            # the diagram is that the two sides are distinct.
            is_response = bool(sip_fields.get("sip.Status-Code"))
            if is_response:
                src_ip, dst_ip = ne_ip, peer_ip
                src_ne, dst_ne = ne_name, "Remote IMS Peer"
            else:
                src_ip, dst_ip = peer_ip, ne_ip
                src_ne, dst_ne = "Remote IMS Peer", ne_name
            tx = {
                "tr_id": str(hdr.get("seq", "")),
                "time_epoch": ts,
                "time_text": time_text,
                "timestamp": ts,
                "protocol": "SIP",
                "_src": src_ip,
                "_dst": dst_ip,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_ne": src_ne if src_ip else "",
                "dst_ne": dst_ne if dst_ip else "",
                "message_type": message_type,
                "interface_type": "Mw" if ne_class in ("A-SBC_WAC", "P-CSCF") else "ISC",
                "interface_family": _interface_family("TRC_MI_SIPC_UP"),
                "call_id": sip_fields.get("sip.Call-ID", ""),
                "session_ids": {"call_id": sip_fields.get("sip.Call-ID", "")},
            }
            tx.update(sip_fields)
            tx["status"] = _success_or_failure(tx, "SIP")
            tx["procedure"] = sip_fields.get("procedure") or message_type
            transactions.append(tx)
            sip_count += 1
            message_types[message_type] = message_types.get(message_type, 0) + 1
            interfaces[tx["interface_type"]] = interfaces.get(tx["interface_type"], 0) + 1
            continue

        if _looks_like_diameter(body):
            diam_fields = _parse_diameter_body(body.hex())
            mt = f"Diameter cmd {diam_fields.get('diameter.cmd.code', '?')}"
            tx = {
                "tr_id": str(hdr.get("seq", "")),
                "time_epoch": ts,
                "time_text": time_text,
                "timestamp": ts,
                "protocol": "Diameter",
                "_src": ne_ip,
                "_dst": "",
                "src_ip": ne_ip,
                "dst_ip": "",
                "src_ne": ne_name,
                "dst_ne": "Diameter Peer",
                "message_type": mt,
                "interface_type": "Diameter",
                "interface_family": "Diameter (other)",
            }
            tx.update(diam_fields)
            tx["status"] = _success_or_failure(tx, "Diameter")
            transactions.append(tx)
            diam_count += 1
            message_types[mt] = message_types.get(mt, 0) + 1
            continue

        log_line = _find_log_line(body)
        if log_line:
            log_findings.append({
                "severity": "warning" if "WARNING" in log_line else "info",
                "group": ne_class or "NE Log",
                "ne": ne_name,
                "time": time_text,
                "message": _redact_identifiers(log_line)[:500],
            })
            log_count += 1
            continue

        other_count += 1

    # Build summary
    epochs = [t["time_epoch"] for t in transactions if t.get("time_epoch")]
    summary = {
        "format": "ptmf",
        "ne_name": ne_name,
        "ne_class": ne_class,
        "ne_ip": ne_ip,
        "ne_version": ne_version,
        "total_records": msg_count_total,
        "total_messages": len(transactions),
        "sip_messages": sip_count,
        "diameter_messages": diam_count,
        "log_lines": log_count,
        "other_records": other_count,
        "unique_call_ids": len({t.get("call_id") for t in transactions if t.get("call_id")}),
        "time_range": {
            "start_epoch": min(epochs) if epochs else None,
            "end_epoch": max(epochs) if epochs else None,
            "duration_seconds": (max(epochs) - min(epochs)) if len(epochs) >= 2 else 0,
        },
        "message_type_counts": dict(sorted(message_types.items(), key=lambda kv: -kv[1])[:20]),
        "interface_counts": dict(sorted(interfaces.items(), key=lambda kv: -kv[1])[:10]),
        "node_types_observed": [ne_class] if ne_class else [],
        "node_count": 1 if ne_ip else 0,
    }

    logger.info("PTMF: classified %d SIP / %d Diameter / %d log / %d other from %d records",
                sip_count, diam_count, log_count, other_count, msg_count_total)

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        with (out / "transactions.json").open("w") as f:
            json.dump(transactions, f, default=str)
        with (out / "summary.json").open("w") as f:
            json.dump(summary, f, indent=2, default=str)
        with (out / "node_map.json").open("w") as f:
            json.dump(node_map, f, indent=2)
        with (out / "log_findings.json").open("w") as f:
            json.dump(log_findings, f, indent=2, default=str)

    return {
        "transactions": transactions,
        "summary": summary,
        "node_map": node_map,
        "log_findings": log_findings,
    }


def format_ptmf_summary_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("total_records"):
        return "## HUAWEI IMS TRACE: No PTMF trace uploaded."
    lines = ["## HUAWEI IMS PTMF TRACE"]
    lines.append(f"- NE: {summary.get('ne_name')} ({summary.get('ne_class')}) {summary.get('ne_version')}")
    lines.append(f"- Records: {summary['total_records']} total, {summary['sip_messages']} SIP, "
                 f"{summary['diameter_messages']} Diameter, {summary['log_lines']} log, "
                 f"{summary['other_records']} other binary")
    tr = summary.get("time_range") or {}
    if tr.get("duration_seconds"):
        lines.append(f"- Duration: {tr['duration_seconds']:.1f}s")
    if summary.get("message_type_counts"):
        top = list(summary["message_type_counts"].items())[:8]
        lines.append("- Top message types: " + ", ".join(f"{k}×{v}" for k, v in top))
    return "\n".join(lines)
