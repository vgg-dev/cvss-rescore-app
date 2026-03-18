from fastapi.testclient import TestClient

import app as app_module


def test_index_serves_html() -> None:
    client = TestClient(app_module.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "CVSS Re-score" in response.text


def test_analyze_endpoint_returns_service_output(monkeypatch) -> None:
    service_output = {
        "cve_id": "CVE-2026-32746",
        "analysis": {"score": 9.4, "severity": "CRITICAL"},
        "strict_analysis": {"score": None, "severity": None},
    }

    def fake_analyze(request):
        assert request.cve_id == "CVE-2026-32746"
        return service_output

    monkeypatch.setattr(app_module, "analyze_cve", fake_analyze)
    client = TestClient(app_module.app)

    response = client.post("/api/analyze", json={"cve_id": "CVE-2026-32746"})

    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == service_output["cve_id"]
    assert body["analysis"]["score"] == 9.4
    assert body["analysis"]["severity"] == "CRITICAL"
    assert body["strict_analysis"]["score"] is None
    assert body["strict_analysis"]["severity"] is None
    assert "comparison" in body["analysis"]
    assert "evidence_quality" in body["analysis"]
