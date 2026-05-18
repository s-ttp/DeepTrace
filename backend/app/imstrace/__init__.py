"""Huawei IMS core trace ingestion (and any future IMS-core trace formats)."""
from .huawei_html import ingest_huawei_ims, detect_huawei_zip

__all__ = ["ingest_huawei_ims", "detect_huawei_zip"]
