import inspect

from fastapi.testclient import TestClient

import app as app_module


def test_analyze_route_is_sync_to_avoid_blocking_event_loop() -> None:
    assert not inspect.iscoroutinefunction(app_module.analyze)


def test_index_serves_html() -> None:
    client = TestClient(app_module.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "CVSS Re-score" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


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


def test_analyze_endpoint_rate_limits(monkeypatch) -> None:
    service_output = {
        "cve_id": "CVE-2026-32746",
        "analysis": {"score": 9.4, "severity": "CRITICAL"},
        "strict_analysis": {"score": None, "severity": None},
    }

    monkeypatch.setattr(app_module, "RATE_LIMIT_MAX_REQUESTS", 1)
    app_module.RATE_LIMIT_BUCKETS.clear()
    monkeypatch.setattr(app_module, "analyze_cve", lambda request: service_output)
    client = TestClient(app_module.app)

    first = client.post("/api/analyze", json={"cve_id": "CVE-2026-32746"})
    second = client.post("/api/analyze", json={"cve_id": "CVE-2026-32746"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "Rate limit exceeded. Please try again later."
