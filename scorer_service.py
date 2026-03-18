import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import ExitStack
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = BASE_DIR / "vendor" / "infer_cvss31_from_references.py"
RAW_CVE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, for example CVE-2026-32746")


def _cve_url(cve_id: str) -> str:
    try:
        _, year, number = cve_id.split("-")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid CVE ID format") from exc

    if len(number) < 5 or not year.isdigit() or not number.isdigit():
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    prefix = number[:2] + "xxx"
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
