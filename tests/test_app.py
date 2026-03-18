from fastapi.testclient import TestClient

import app as app_module


def test_index_serves_html() -> None:
    client = TestClient(app_module.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "CVSS Re-score" in response.text


def test_analyze_endpoint_returns_service_output(monkeypatch) -> None:
    expected = {
        "cve_id": "CVE-2026-32746",
        "analysis": {"score": 9.4, "severity": "CRITICAL"},
        "strict_analysis": {"score": None, "severity": None},
    }

    def fake_analyze(request):
        assert request.cve_id == "CVE-2026-32746"
        return expected

    monkeypatch.setattr(app_module, "analyze_cve", fake_analyze)
    client = TestClient(app_module.app)

    response = client.post("/api/analyze", json={"cve_id": "CVE-2026-32746"})

    assert response.status_code == 200
    assert response.json() == expected
