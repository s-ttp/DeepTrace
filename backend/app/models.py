"""Data models for PCAP Analyzer"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from enum import Enum


class AnalysisStatus(str, Enum):
    UPLOADING = "uploading"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class FlowInfo(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "Unknown"
    packet_count: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    gtp: Optional[Dict[str, Any]] = None
    llm_insight: Optional[str] = None


class AnalysisSummary(BaseModel):
    total_flows: int
    total_packets: int
    protocols: List[str]
    duration: float = 0.0


class AnalysisResult(BaseModel):
    flows: List[Dict[str, Any]]
    root_cause_analysis: str
    summary: AnalysisSummary


class AnalysisJob(BaseModel):
    job_id: str
    status: AnalysisStatus
    progress: int
    filename: str
    error: Optional[str] = None
    results: Optional[AnalysisResult] = None


class UploadResponse(BaseModel):
    job_id: str


class ProgressUpdate(BaseModel):
    progress: int
    message: str
