"""
FastAPI application for Malicious Email Scorer backend.
Exposes a single POST endpoint for email analysis.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.models import EmailAnalysisRequest, EmailAnalysisResponse
from app.scoring_engine import ScoringEngine

app = FastAPI(
    title="Malicious Email Scorer API",
    description="Privacy-first email maliciousness detection via rules-based scoring",
    version="1.0.0",
)

# CORS configuration (allow Gmail Add-on to call this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "service": "Malicious Email Scorer API",
        "status": "operational",
        "version": "1.0.0",
    }


@app.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze an email and return maliciousness score with explainable verdict.

    This endpoint treats all input as untrusted and performs static analysis only.
    No external API calls or DNS lookups are performed.
    """
    try:
        # Initialize scoring engine
        engine = ScoringEngine()

        # Run analysis
        score, risk_level, explanations = engine.analyze(
            sender=request.sender,
            subject=request.subject,
            body_html=request.body_html,
            body_text=request.body_text,
            attachment_extensions=request.attachment_extensions,
            headers=request.headers,
        )

        # Get verdict message
        verdict = ScoringEngine.get_verdict(risk_level)

        # Build response
        return EmailAnalysisResponse(
            score=score,
            risk_level=risk_level,
            verdict=verdict,
            explanations=explanations,
        )

    except Exception as e:
        # Log error and return generic error response
        # In production, use proper logging
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Detailed health check for monitoring."""
    return {
        "status": "healthy",
        "components": {
            "scoring_engine": "operational",
            "api": "operational",
        },
    }