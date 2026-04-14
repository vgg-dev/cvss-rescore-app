import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from scorer_service import AnalyzeRequest, AnalyzeResponse, ErrorResponse, analyze_cve


BASE_DIR = Path(__file__).resolve().parent
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "12"))
RATE_LIMIT_BUCKETS: defaultdict[str, deque[float]] = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()

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


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if request.url.path not in {"/docs", "/redoc", "/openapi.json"}:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'",
        )
    return response


@app.middleware("http")
async def analyze_rate_limit(request: Request, call_next) -> Response:
    if request.url.path != "/api/analyze":
        return await call_next(request)

    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS[client]
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please try again later."},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        bucket.append(now)
    return await call_next(request)


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
        503: {
            "model": ErrorResponse,
            "description": "The scorer is busy and the request could not be queued.",
        },
        504: {
            "model": ErrorResponse,
            "description": "The scorer timed out.",
        },
        429: {
            "model": ErrorResponse,
            "description": "Too many analyze requests from the same client.",
        },
    },
)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_cve(request)
