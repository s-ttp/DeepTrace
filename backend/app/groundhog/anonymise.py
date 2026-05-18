"""Subscriber-identifier anonymisation for Groundhog artifacts.

Replaces raw IMSI / MSISDN / GUTI / TMSI / IMEI / UE_IP values with
deterministic, opaque pseudonyms of the form ``IMSI_abcd1234``.

Design notes
------------
- Deterministic *within a single process*: the same raw value always maps
  to the same pseudonym so cross-plane correlation still works.
- *Not* deterministic across process restarts: the HMAC secret is a
  per-process random value (`secrets.token_bytes`), so pseudonyms cannot
  be brute-forced offline by an attacker who finds an old artifact and
  knows the format. This matches the project's privacy stance: the
  daily restart wipes state, including the pseudonym keyspace.
- Stripping is preferred over hashing for fields that aren't useful for
  joining (`raw` source rows, free-form labels): see ``redact_event``.
"""
import hmac
import hashlib
import secrets
from typing import Any, Dict, Optional

# Per-process secret. Rotates on restart, which is intentional.
_SECRET = secrets.token_bytes(32)

# Fields on a normalized radio event that hold subscriber identifiers and
# should never be persisted, returned, or sent to an LLM verbatim.
SENSITIVE_EVENT_FIELDS = ("imsi", "msisdn", "guti", "tmsi", "imei", "supi", "ue_ip")

# Substrings that, if present in a `raw` source-row column name (case-insensitive),
# indicate the value is a subscriber identifier and should be redacted in place.
# Anything not matching stays — radio detectors need vendor result/cause codes
# (RRC_RECONFIG_RESULT, CAUSE, release_cause, etc.) which live in `raw`.
SENSITIVE_RAW_KEY_TOKENS = (
    "imsi", "msisdn", "subscriber id", "subscriber_id",
    "guti", "tmsi", "supi", "imei",
    "ue ip", "ue_ip", "ue ip address", "pdn address", "ip address", "ip_address",
    "phone", "msin",
)


def pseudonymise(kind: str, value: Any) -> Optional[str]:
    """Return a stable pseudonym for ``value`` under the given ``kind`` label.

    Returns None if ``value`` is None/empty so callers can preserve "absent".
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    digest = hmac.new(_SECRET, f"{kind}|{s}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{kind.upper()}_{digest[:8]}"


def _is_sensitive_raw_key(key: str) -> bool:
    k = str(key).lower()
    return any(token in k for token in SENSITIVE_RAW_KEY_TOKENS)


def redact_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``event`` with subscriber identifiers pseudonymised.

    ``raw`` (the original source row) is *not* dropped — radio detectors
    legitimately read vendor result/cause codes from it. Instead we walk
    ``raw`` and pseudonymise any value whose column name looks like a
    subscriber identifier (IMSI/MSISDN/GUTI/TMSI/IMEI/UE_IP variants).
    Everything else (RRC_RECONFIG_RESULT, CAUSE, release_cause, KPIs, …)
    is preserved verbatim so the downstream detectors keep working.
    """
    out = dict(event)
    for field in SENSITIVE_EVENT_FIELDS:
        if out.get(field):
            out[field] = pseudonymise(field, out[field])
    raw = out.get("raw")
    if isinstance(raw, dict) and raw:
        clean_raw = {}
        for k, v in raw.items():
            if _is_sensitive_raw_key(k) and v not in (None, ""):
                clean_raw[k] = pseudonymise(k, v)
            else:
                clean_raw[k] = v
        out["raw"] = clean_raw
    elif raw is None:
        out["raw"] = {}
    return out


def redact_events(events):
    """Apply :func:`redact_event` to every event in an iterable."""
    return [redact_event(e) for e in events]
