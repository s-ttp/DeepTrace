"""
FastAPI router for chat endpoints.
Provides POST /api/chat/query for trace-aware Q&A.
"""
import logging
from typing import Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException

from .chatbot_service import chat_query

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(tags=["chat"])


class ChatRequest(BaseModel):
    """Request model for chat query."""
    job_id: str = Field(..., description="Analysis job ID")
    message: str = Field(..., description="User's question", min_length=1, max_length=2000)
    mode: str = Field("trace", description="Chat mode: 'trace' or 'explain'")


class ChatResponse(BaseModel):
    """Response model for chat query."""
    answer: str = Field(..., description="AI response")
    citations: list = Field(default_factory=list, description="Evidence citations")


# Import analyses dict from main module
# This is done at runtime to avoid circular imports
def get_analyses():
    from ..main import analyses
    return analyses


@router.post("/query", response_model=ChatResponse)
async def query_chat(request: ChatRequest):
    """
    Process a chat query about a specific trace.
    
    Modes:
    - "trace": Strictly grounded in trace evidence (default)
    - "explain": Educational mode for telecom concepts
    """
    logger.info(f"Chat query for job {request.job_id}, mode: {request.mode}")
    
    # Validate mode
    if request.mode not in ("trace", "explain"):
        raise HTTPException(
            status_code=400,
            detail="Invalid mode. Use 'trace' or 'explain'."
        )
    
    # Get analysis data
    analyses = get_analyses()
    
    if request.job_id not in analyses:
        raise HTTPException(
            status_code=404,
            detail="Analysis job not found. Please run an analysis first."
        )
    
    analysis = analyses[request.job_id]
    
    if analysis.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Analysis not complete. Current status: {analysis.get('status')}"
        )
    
    # Process query
    result = await chat_query(
        analysis_data=analysis,
        user_message=request.message,
        mode=request.mode
    )
    
    return ChatResponse(
        answer=result["answer"],
        citations=result.get("citations", [])
    )


@router.get("/health")
async def chat_health():
    """Health check for chat service."""
    return {"status": "ok", "service": "chat"}
