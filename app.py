from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from scorer_service import AnalyzeRequest, AnalyzeResponse, ErrorResponse, analyze_cve


BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="CVSS Re-score Workbench API",
    version="0.1.0",
    summary="Reference-based CVSS v3.1 re-scoring API with independent and strict analysis modes.",
    description=(
        "Fetches a CVE record from the CVE Project dataset, runs the bundled reference-based "
        "CVSS v3.1 scorer, and returns both an independent result and a strict no-fallback result. "
        "Use `/docs` for Swagger UI and `/redoc` for the reference view."
    ),
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get(
    "/",
    summary="Serve the browser UI",
    description="Returns the static HTML interface for the CVSS Re-score Workbench.",
)
async def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a CVE",
    description=(
        "Accepts a CVE ID, downloads the matching CVE JSON from the CVE Project repository, "
        "runs the bundled scorer in both independent and strict modes, and returns the resulting "
        "vectors, scores, confidence indicators, and comparison details."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Invalid CVE ID format.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid CVE ID format. Expected CVE-YYYY-NNNN or longer."}
                }
            },
        },
        404: {
            "model": ErrorResponse,
            "description": "The CVE JSON was not found upstream.",
            "content": {
                "application/json": {"example": {"detail": "CVE JSON not found: CVE-2026-99999"}}
            },
        },
        502: {
            "model": ErrorResponse,
            "description": "The app could not fetch the upstream CVE JSON.",
        },
        500: {
            "model": ErrorResponse,
            "description": "The local scorer failed or returned invalid output.",
        },
    },
)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_cve(request)
