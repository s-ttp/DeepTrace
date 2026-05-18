"""
Case Manager - Manages iterative analysis cases with multiple uploads.

Each case has a unique case_id and a directory structure:
  artifacts/<case_id>/
    meta.json
    pcap/
    groundhog/
    correlation/
    final/
"""
import os
import shutil
import uuid
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
UPLOADS_DIR = Path(__file__).parent.parent / "uploads"


def wipe_all_cases() -> Dict[str, int]:
    """Delete every case dir under artifacts/ and every file in uploads/.

    Real-time troubleshooting design: at any moment the disk should hold at most
    the *current* case. Called from the FastAPI lifespan on startup (which
    also fires on the daily 23:00 cron restart) and from the case-create
    endpoint (so the previous case is wiped the moment a new one begins).
    """
    removed_cases = 0
    removed_uploads = 0
    if ARTIFACTS_DIR.exists():
        for entry in ARTIFACTS_DIR.iterdir():
            if entry.is_dir() and entry.name != ".cache" and not entry.name.startswith("."):
                try:
                    shutil.rmtree(entry)
                    removed_cases += 1
                except Exception as e:
                    logger.warning("Could not remove %s: %s", entry, e)
    if UPLOADS_DIR.exists():
        for entry in UPLOADS_DIR.iterdir():
            if entry.is_file() and entry.name != ".gitkeep" and not entry.name.startswith("."):
                try:
                    entry.unlink()
                    removed_uploads += 1
                except Exception as e:
                    logger.warning("Could not remove %s: %s", entry, e)
    if removed_cases or removed_uploads:
        logger.info("Wiped %d case dir(s) and %d upload file(s) from disk", removed_cases, removed_uploads)
    return {"cases_removed": removed_cases, "uploads_removed": removed_uploads}


def wipe_case(case_id: str) -> bool:
    """Remove a single case's artifacts directory + any matching upload files."""
    case_dir = ARTIFACTS_DIR / case_id
    removed = False
    if case_dir.exists() and case_dir.is_dir():
        try:
            shutil.rmtree(case_dir)
            removed = True
        except Exception as e:
            logger.warning("Could not remove %s: %s", case_dir, e)
    if UPLOADS_DIR.exists():
        for entry in UPLOADS_DIR.iterdir():
            if entry.is_file() and entry.name.startswith(case_id):
                try:
                    entry.unlink()
                except Exception as e:
                    logger.warning("Could not remove %s: %s", entry, e)
    if removed:
        logger.info("Wiped case %s from disk", case_id)
    return removed


def create_case() -> Dict[str, Any]:
    """Create a new case with directory structure. Returns case metadata."""
    case_id = str(uuid.uuid4())
    case_dir = ARTIFACTS_DIR / case_id

    # Create directory structure
    for subdir in ["pcap", "groundhog", "correlation", "final"]:
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)

    meta = {
        "case_id": case_id,
        "created_at": time.time(),
        "updated_at": time.time(),
        "pcap": None,        # {"filename": ..., "uploaded_at": ..., "analyzed": False}
        "groundhog": None,   # {"filename": ..., "format": ..., "uploaded_at": ..., "analyzed": False}
        "status": "created",
        "analysis_runs": [],
    }

    _write_meta(case_id, meta)
    logger.info(f"Created case {case_id} at {case_dir}")
    return meta


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    """Read case metadata. Returns None if case doesn't exist."""
    meta_path = ARTIFACTS_DIR / case_id / "meta.json"
    if not meta_path.exists():
        return None
    with open(meta_path, "r") as f:
        return json.load(f)


def update_case_meta(case_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Merge updates into existing meta.json and return updated meta."""
    meta = get_case(case_id)
    if meta is None:
        raise ValueError(f"Case {case_id} not found")
    meta.update(updates)
    meta["updated_at"] = time.time()
    _write_meta(case_id, meta)
    return meta


def get_case_dir(case_id: str) -> Path:
    """Return the case artifacts directory path."""
    return ARTIFACTS_DIR / case_id


def register_pcap(case_id: str, filename: str, file_path: str) -> Dict[str, Any]:
    """Register a PCAP file upload for the case."""
    return update_case_meta(case_id, {
        "pcap": {
            "filename": filename,
            "file_path": file_path,
            "uploaded_at": time.time(),
            "analyzed": False,
        }
    })


def register_groundhog(case_id: str, filename: str, file_path: str, fmt: str) -> Dict[str, Any]:
    """Register a Groundhog radio trace upload for the case."""
    return update_case_meta(case_id, {
        "groundhog": {
            "filename": filename,
            "file_path": file_path,
            "format": fmt,
            "uploaded_at": time.time(),
            "analyzed": False,
        }
    })


def register_huawei_ims(case_id: str, filename: str, file_path: str,
                         fmt: str = "huawei_html_zip") -> Dict[str, Any]:
    """Register a Huawei IMS trace upload.

    ``fmt`` is one of:
      - ``huawei_html_zip`` — Service Trace .zip (sequence-diagram bundle)
      - ``ptmf`` — NE-side binary Performance Trace
    """
    return update_case_meta(case_id, {
        "huawei_ims": {
            "filename": filename,
            "file_path": file_path,
            "format": fmt,
            "uploaded_at": time.time(),
            "analyzed": False,
        }
    })


def record_analysis_run(case_id: str, run_info: Dict[str, Any]) -> Dict[str, Any]:
    """Append an analysis run record to the case."""
    meta = get_case(case_id)
    if meta is None:
        raise ValueError(f"Case {case_id} not found")
    meta.setdefault("analysis_runs", []).append({
        **run_info,
        "timestamp": time.time(),
    })
    meta["updated_at"] = time.time()
    _write_meta(case_id, meta)
    return meta


def _write_meta(case_id: str, meta: Dict[str, Any]):
    """Write meta.json to disk."""
    meta_path = ARTIFACTS_DIR / case_id / "meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
