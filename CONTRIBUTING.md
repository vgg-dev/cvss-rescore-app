# Contributing

Thanks for contributing to `cvss-rescore-app`.

## Development

```powershell
Set-Location C:\Users\vgera\cvss-scorer-app
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

## Before Opening a Pull Request

Run a quick syntax check:

```powershell
python -m py_compile app.py scorer_service.py vendor\infer_cvss31_from_references.py
```

Then verify the app locally with at least one known CVE, for example:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/analyze" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"cve_id":"CVE-2026-32746"}'
```

## Contribution Guidelines

- Keep changes focused and easy to review
- Prefer simple, inspectable logic over opaque behavior
- Preserve the distinction between independent mode and strict mode
- Avoid introducing hidden filesystem leakage or leftover temp artifacts
- Update the README when user-facing behavior changes
