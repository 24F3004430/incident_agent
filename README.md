# Observable Incident Triage agent (ga5-incident-agent/v2)

FastAPI + SQLite. One model call per new runId (planner.py); everything else (receipts, retries, approvals, trace) is a deterministic state machine over stored state (engine.py, tracing.py).

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Open http://127.0.0.1:8000/docs.

## Test
```bash
pytest -q
```

Set `DATABASE_PATH` to change the SQLite file. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable best-effort OTLP/HTTP export.

## Routes
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`
- `GET /health`

## Deploy on Render
1. Push this repo to GitHub.
2. Render dashboard -> New -> Blueprint -> pick the repo (it reads `render.yaml`).
3. Fill in the `LLM_*` secrets when prompted. Deploy.
4. Base URL to submit: `https://<your-service>.onrender.com` (no trailing path).
