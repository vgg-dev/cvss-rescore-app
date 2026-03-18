import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field


BASE_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = BASE_DIR / "vendor" / "infer_cvss31_from_references.py"
RAW_CVE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(
        ...,
        description="CVE identifier in the form CVE-YYYY-NNNN or longer.",
        examples=["CVE-2026-4366", "CVE-2026-32746"],
    )


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Human-readable error message.")


class ComparisonModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    original_vector: str | None = Field(default=None, description="Published or source vector, if available.")
    original_score: float | None = Field(default=None, description="Published or source numeric CVSS score.")
    original_source: str | None = Field(default=None, description="Origin of the published score, such as CNA.")
    rescored_vector: str | None = Field(default=None, description="Re-scored CVSS v3.1 vector.")
    rescored_score: float | None = Field(default=None, description="Re-scored numeric CVSS value.")
    rescored_severity: str | None = Field(default=None, description="Severity for the re-scored value.")
    score_delta: float | None = Field(default=None, description="Difference between re-scored and published values.")
    changed_metrics: dict[str, Any] = Field(
        default_factory=dict,
        description="Metrics that changed between the published and re-scored vectors.",
    )


class EvidenceQualityModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    evidence_backed_metrics: list[str] = Field(
        default_factory=list,
        description="Metrics supported directly by advisory or reference evidence.",
    )
    fallback_metrics: list[str] = Field(
        default_factory=list,
        description="Metrics filled using fallback defaults in independent mode.",
    )
    undetermined_metrics: list[str] = Field(
        default_factory=list,
        description="Metrics left unresolved in strict mode.",
    )


class AnalysisModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    vector: str | None = Field(default=None, description="Final CVSS v3.1 vector for this analysis mode.")
    score: float | None = Field(default=None, description="Final numeric CVSS score for this analysis mode.")
    severity: str | None = Field(default=None, description="Severity associated with the final score.")
    confidence: str | None = Field(default=None, description="Confidence assessment for the independent analysis.")
    low_confidence: bool | None = Field(default=None, description="True when the independent result needs review.")
    comparison: ComparisonModel = Field(
        default_factory=ComparisonModel,
        description="Published versus re-scored comparison details.",
    )
    evidence_quality: EvidenceQualityModel = Field(
        default_factory=EvidenceQualityModel,
        description="Breakdown of evidence-backed, fallback, and undetermined metrics.",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Per-metric evidence snippets and inference details from the scorer.",
    )
    reference_fetch_errors: list[Any] = Field(
        default_factory=list,
        description="Reference retrieval errors encountered while gathering source material.",
    )


class AnalyzeResponse(BaseModel):
    cve_id: str = Field(..., description="Normalized uppercase CVE identifier.")
    analysis: AnalysisModel = Field(..., description="Independent analysis result using fallback defaults as needed.")
    strict_analysis: AnalysisModel = Field(
        ...,
        description="Strict analysis result, which refuses to score unsupported metrics.",
    )


def _cve_url(cve_id: str) -> str:
    try:
        _, year, number = cve_id.split("-")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Expected CVE-YYYY-NNNN or longer.") from exc

    if len(number) < 4 or not year.isdigit() or not number.isdigit():
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Expected CVE-YYYY-NNNN or longer.")

    prefix = number[:-3] + "xxx"
    return f"{RAW_CVE_BASE}/{year}/{prefix}/{cve_id}.json"


def _fetch_cve_json(cve_id: str, temp_dir: Path) -> Path:
    url = _cve_url(cve_id)
    out_path = temp_dir / f"{cve_id}.json"
    request = urllib.request.Request(url, headers={"User-Agent": "cvss-rescore-app/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            out_path.write_bytes(response.read())
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=404, detail=f"CVE JSON not found: {cve_id}") from exc
    except urllib.error.URLError as exc:
        raise HTTPException(status_code=502, detail=f"Unable to fetch CVE JSON: {exc.reason}") from exc
    return out_path


def _run_inference(cve_json_path: Path, strict: bool) -> dict:
    command = ["python", str(SCRIPT_PATH), "--cve-json", str(cve_json_path)]
    if strict:
        command.append("--strict-undetermined")

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Scoring failed"
        raise HTTPException(status_code=500, detail=detail)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Scorer returned invalid JSON") from exc


def analyze_cve(request: AnalyzeRequest) -> dict:
    cve_id = request.cve_id.strip().upper()
    with ExitStack() as stack:
        temp_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="cvss-rescore-")))
        cve_json_path = _fetch_cve_json(cve_id, temp_dir)
        normal = _run_inference(cve_json_path, strict=False)
        strict = _run_inference(cve_json_path, strict=True)
        return {
            "cve_id": cve_id,
            "analysis": normal,
            "strict_analysis": strict,
        }
