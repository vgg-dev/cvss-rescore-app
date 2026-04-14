import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi import HTTPException

import scorer_service
from scorer_service import AnalyzeRequest, _cve_url, _run_inference, analyze_cve


def test_cve_url_supports_four_digit_sequence() -> None:
    url = _cve_url("CVE-2026-4366")
    assert url.endswith("/2026/4xxx/CVE-2026-4366.json")


def test_cve_url_supports_five_digit_sequence() -> None:
    url = _cve_url("CVE-2026-32746")
    assert url.endswith("/2026/32xxx/CVE-2026-32746.json")


@pytest.mark.parametrize("cve_id", ["CVE-2026-123", "CVE-20AA-1234", "NOT-A-CVE"])
def test_cve_url_rejects_invalid_format(cve_id: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        _cve_url(cve_id)

    assert exc_info.value.status_code == 400
    assert "CVE-YYYY-NNNN or longer" in exc_info.value.detail


def test_analyze_cve_cleans_up_temporary_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    request = AnalyzeRequest(cve_id="cve-2026-4366")
    seen = {}
    workspace_temp = Path(__file__).resolve().parent / "tmp-cvss-rescore"

    class LocalTemporaryDirectory:
        def __init__(self, prefix: str) -> None:
            self.path = workspace_temp.parent / f"{prefix}test"

        def __enter__(self) -> str:
            if self.path.exists():
                shutil.rmtree(self.path, ignore_errors=False)
            self.path.mkdir(parents=True, exist_ok=False)
            return str(self.path)

        def __exit__(self, exc_type, exc, tb) -> None:
            shutil.rmtree(self.path, ignore_errors=False)

    def fake_fetch(cve_id: str, temp_dir: Path) -> Path:
        assert cve_id == "CVE-2026-4366"
        seen["temp_dir"] = temp_dir
        cve_path = temp_dir / f"{cve_id}.json"
        cve_path.write_text("{}", encoding="utf-8")
        return cve_path

    def fake_inference(cve_json_path: Path, strict: bool) -> dict:
        assert cve_json_path.exists()
        return {
            "vector": None if strict else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            "score": None if strict else 8.6,
            "severity": None if strict else "HIGH",
            "comparison": {
                "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
                "original_score": 8.2,
                "original_source": "cna",
                "rescored_vector": None if strict else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                "rescored_score": None if strict else 8.6,
                "rescored_severity": None if strict else "HIGH",
                "score_delta": None if strict else 0.4,
                "changed_metrics": {},
            },
            "evidence_quality": {
                "evidence_backed_metrics": ["AV"],
                "fallback_metrics": [],
                "undetermined_metrics": ["AC"] if strict else [],
            },
        }

    monkeypatch.setattr(scorer_service.tempfile, "TemporaryDirectory", LocalTemporaryDirectory)
    monkeypatch.setattr(scorer_service, "_fetch_cve_json", fake_fetch)
    monkeypatch.setattr(scorer_service, "_run_inference", fake_inference)

    result = analyze_cve(request)

    assert result["cve_id"] == "CVE-2026-4366"
    assert seen["temp_dir"].name.startswith("cvss-rescore-")
    assert not seen["temp_dir"].exists()


def test_run_inference_returns_generic_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=kwargs.get("args", "scorer"), timeout=1)

    monkeypatch.setattr(scorer_service.subprocess, "run", fake_run)

    with pytest.raises(HTTPException) as exc_info:
        _run_inference(Path("CVE-2026-4366.json"), strict=False)

    assert exc_info.value.status_code == 504
    assert exc_info.value.detail == "Scoring timed out. Please try again later."


def test_run_inference_returns_generic_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    result = subprocess.CompletedProcess(args=["scorer"], returncode=1, stdout="secret path", stderr="traceback")
    monkeypatch.setattr(scorer_service.subprocess, "run", lambda *args, **kwargs: result)

    with pytest.raises(HTTPException) as exc_info:
        _run_inference(Path("CVE-2026-4366.json"), strict=False)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Scoring failed. Please try again later."
