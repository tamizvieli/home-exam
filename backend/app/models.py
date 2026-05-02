"""
Pydantic models for request and response validation.
Enforces the API contract defined in the specification.
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    """Request payload from Gmail Add-on to backend."""

    sender: str = Field(..., description="Email address of the sender")
    subject: str = Field(..., description="Email subject line")
    body_html: str = Field(..., description="Full HTML body of the email")
    body_text: str = Field(..., description="Plain text version of the email body")
    attachment_extensions: List[str] = Field(
        default_factory=list,
        description="List of file extensions (e.g., ['.pdf', '.exe'])"
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Email headers, specifically authentication_results"
    )


class EmailAnalysisResponse(BaseModel):
    """Response payload from backend to Gmail Add-on."""

    score: int = Field(..., ge=0, le=100, description="Final maliciousness score (0-100)")
    risk_level: str = Field(..., description="Risk category: safe | suspicious | dangerous")
    verdict: str = Field(..., description="Human-readable verdict message (Hebrew)")
    explanations: List[str] = Field(
        default_factory=list,
        description="List of triggered rule explanations (Hebrew)"
    )