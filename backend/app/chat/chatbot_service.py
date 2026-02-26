"""
Chatbot service for trace-aware Q&A.
Uses Kimi K2.5 model via existing LLM client.
"""
import json
import logging
from typing import Dict, Any, Optional, List

from ..llm_service import get_llm_client
from .prompts import (
    TRACE_MODE_SYSTEM,
    EXPLAINER_MODE_SYSTEM,
    format_trace_prompt,
    format_explainer_prompt,
)
from .context_builder import build_trace_context, context_to_json

logger = logging.getLogger(__name__)


async def chat_query(
    analysis_data: Dict[str, Any],
    user_message: str,
    mode: str = "trace"
) -> Dict[str, Any]:
    """
    Process a chat query against trace context.
    
    Args:
        analysis_data: The full analysis dict from analyses[job_id]
        user_message: The user's question
        mode: "trace" for grounded mode, "explain" for educational mode
        
    Returns:
        Dict with 'answer' and optional 'citations'
    """
    logger.info(f"Chat query received - mode: {mode}, message: {user_message[:50]}...")
    
    # Build context from analysis
    context = build_trace_context(analysis_data)
    context_json = context_to_json(context, indent=False)
    
    # Log context size for monitoring
    context_size = len(context_json)
    logger.info(f"Context size: {context_size} chars")
    
    # Select system prompt and format user prompt based on mode
    if mode == "trace":
        system_prompt = TRACE_MODE_SYSTEM
        user_prompt = format_trace_prompt(context_json, user_message)
    else:
        system_prompt = EXPLAINER_MODE_SYSTEM
        user_prompt = format_explainer_prompt(context_json, user_message)
    
    try:
        client = get_llm_client()
        
        # Use Kimi K2.5 with temperature=1 (API requirement)
        completion = client.chat.completions.create(
            model="kimi-k2.5",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=1,  # Required by Kimi API
            max_tokens=1200
        )
        
        answer = completion.choices[0].message.content
        
        if answer is None:
            answer = "I was unable to generate a response. Please try rephrasing your question."
        
        # Extract citations if present (look for evidence markers)
        citations = extract_citations(answer, context)
        
        logger.info(f"Chat response generated - length: {len(answer)}")
        
        return {
            "answer": answer.strip(),
            "citations": citations
        }
        
    except Exception as e:
        logger.error(f"Chat query failed: {e}")
        return {
            "answer": f"I encountered an error processing your question: {str(e)}",
            "citations": []
        }


def extract_citations(answer: str, context: Dict[str, Any]) -> List[str]:
    """
    Extract evidence citations from the answer.
    Looks for references to specific findings, flows, or observations.
    """
    citations = []
    
    # Check if answer references specific elements
    answer_lower = answer.lower()
    
    # Check for root cause references
    for i, cause in enumerate(context.get("root_causes", [])):
        issue = cause.get("issue", "")
        if issue.lower() in answer_lower:
            citations.append(f"Root Cause: {issue}")
    
    # Check for observation references
    for obs in context.get("observations", []):
        finding = obs.get("finding", "")
        if len(finding) > 10 and finding[:20].lower() in answer_lower:
            citations.append(f"Observation: {obs.get('category', 'Unknown')}")
    
    # Check for protocol references
    for proto in context.get("capture_summary", {}).get("observed_protocols", []):
        if proto.lower() in answer_lower:
            citations.append(f"Protocol: {proto}")
    
    # Deduplicate
    return list(dict.fromkeys(citations))[:5]
