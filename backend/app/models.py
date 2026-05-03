"""
Pydantic models for request/response validation.
Ensures all email data is properly validated before analysis.
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional


class EmailAnalysisRequest(BaseModel):
    """
    Request model for email analysis.

    All fields have sensible defaults to handle edge cases where
    Gmail Add-on might send partial data.
    """
    sender: str = Field(default="", description="Email sender address")
    subject: str = Field(default="", description="Email subject line")
    body_html: str = Field(default="", description="Email body in HTML format")
    body_text: str = Field(default="", description="Email body in plain text format")
    attachment_extensions: List[str] = Field(default_factory=list, description="List of attachment file extensions")
    headers: Dict[str, str] = Field(default_factory=dict, description="Email headers (e.g., authentication_results)")

    @validator('sender', 'subject', 'body_html', 'body_text', pre=True)
    def empty_string_to_default(cls, v):
        """Convert None to empty string for text fields."""
        return v if v is not None else ""

    @validator('attachment_extensions', pre=True)
    def empty_list_to_default(cls, v):
        """Convert None to empty list for attachments."""
        return v if v is not None else []

    @validator('headers', pre=True)
    def empty_dict_to_default(cls, v):
        """Convert None to empty dict for headers."""
        return v if v is not None else {}

    class Config:
        schema_extra = {
            "example": {
                "sender": "urgent@phishing.tk",
                "subject": "URGENT: Verify your account",
                "body_html": "<html><body>Click <a href='http://bit.ly/fake'>here</a></body></html>",
                "body_text": "Click here to verify your password",
                "attachment_extensions": [".exe"],
                "headers": {
                    "authentication_results": "spf=fail; dkim=none"
                }
            }
        }


class EmailAnalysisResponse(BaseModel):
    """
    Response model for email analysis results.

    Provides score, risk level, verdict (Hebrew), and detailed explanations.
    """
    score: int = Field(..., ge=0, le=100, description="Maliciousness score (0-100)")
    risk_level: str = Field(..., description="Risk level: safe, suspicious, or dangerous")
    verdict: str = Field(..., description="Hebrew verdict message")
    explanations: List[str] = Field(..., description="List of Hebrew explanations for triggered rules")

    class Config:
        schema_extra = {
            "example": {
                "score": 100,
                "risk_level": "dangerous",
                "verdict": "סכנה - חשד גבוה לפישינג/הונאה",
                "explanations": [
                    "זהות השולח לא אומתה (DKIM/SPF)",
                    "השולח משתמש בסיומת כתובת חשודה",
                    "זוהו קישורים מוסווים או מקוצרים"
                ]
            }
        }