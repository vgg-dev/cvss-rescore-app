from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from scorer_service import AnalyzeRequest, analyze_cve


BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="CVSS Re-score App", version="0.1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    return analyze_cve(request)
