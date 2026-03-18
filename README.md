# CVSS Re-score App

Small FastAPI app that wraps the local `cve-rescore-cvss31` skill and exposes a simple browser UI.

The app is self-contained for deployment: it includes a bundled copy of the reference-based scorer in [vendor/infer_cvss31_from_references.py](/Users/vgera/cvss-scorer-app/vendor/infer_cvss31_from_references.py) and does not depend on the local `.codex` skills directory.

## Run

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

Then open `http://127.0.0.1:8000`.

## Notes

- The app fetches CVE JSON from the CVE Project raw repository.
- The backend runs the bundled reference-based scorer in normal and strict modes.
- Output includes the raw scorer JSON to make review easier.

## Render

This repo includes [render.yaml](/Users/vgera/cvss-scorer-app/render.yaml) for Render deployment.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
