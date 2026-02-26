"""
Groundhog/CovMo Radio Trace Ingestion Module

Supports: HTML, CSV, XLS/XLSX, JSON, XML formats.
Normalizes all formats to a unified radio event schema.
"""
from .ingest import ingest_groundhog

__all__ = ["ingest_groundhog"]
