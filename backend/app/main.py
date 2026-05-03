"""
Malicious Email Scorer - FastAPI Backend
Privacy-first email security analysis API
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.models import EmailAnalysisRequest, EmailAnalysisResponse
from app.scoring_engine import ScoringEngine

app = FastAPI(
    title="Malicious Email Scorer API",
    description="Privacy-first email security analysis using deterministic heuristics",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production to ["https://mail.google.com", "https://script.google.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """
    Health check endpoint.

    Returns:
        dict: Simple status message
    """
    return {"status": "online", "service": "Malicious Email Scorer API"}


@app.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyzes an email for malicious content using 6 rule categories.

    Privacy Note: This endpoint does NOT log email content.
    All analysis is performed in-memory and discarded after response.

    Args:
        request (EmailAnalysisRequest): Email data including sender, subject, body, attachments

    Returns:
        EmailAnalysisResponse: Analysis results with score (0-100), risk level, and explanations

    Raises:
        HTTPException: 400 if validation fails, 500 if analysis error
    """
    try:
        # PRIVACY: Never log email content - only metadata for debugging
        # NO: logger.info(f"Analyzing email: {request.subject}")
        # YES: logger.info("Email analysis request received")

        engine = ScoringEngine()
        score, risk_level, explanations = engine.analyze(
            sender=request.sender or "",  # Handle None/empty sender
            subject=request.subject or "",  # Handle None/empty subject
            body_html=request.body_html or "",
            body_text=request.body_text or "",
            attachment_extensions=request.attachment_extensions or [],
            headers=request.headers or {}
        )

        verdict = ScoringEngine.get_verdict(risk_level)

        return EmailAnalysisResponse(
            score=score,
            risk_level=risk_level,
            verdict=verdict,
            explanations=explanations
        )

    except Exception as e:
        # PRIVACY: Log error type, NOT email content
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(type(e).__name__)}")