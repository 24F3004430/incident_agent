import json, logging, re, time
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
import engine, planner, store
from asgi_wrap import Wrap, REQUESTS, SHAPES, shape

PROFILE = "ga5-incident-agent/v2"
log = logging.getLogger("uvicorn.error")
app = FastAPI(title="Incident agent", docs_url=None, redoc_url=None, openapi_url=None)
store.init_db()

def err(code, msg):  # generic messages only: never echo request content
    return JSONResponse({"error": msg}, status_code=code)

@app.exception_handler(RequestValidationError)
async def _v(_req, _exc): return err(422, "invalid request")

@app.exception_handler(Exception)
async def _e(_req, exc):
    log.error("unhandled %s", type(exc).__name__, exc_info=exc)
    return err(500, "internal error")

app.router.redirect_slashes = False

@app.get("/debug/requests")
def debug_requests():
    return {"requests": list(reversed(REQUESTS)), "createShapes": list(reversed(SHAPES))}

@app.get("/health")
def health(): return {"status": "ok"}

def _validate(b):
    def ne(x): return isinstance(x, str) and x.strip() != ""
    inc, pol = b.get("incident"), b.get("policy")
    if not (ne(b.get("runId")) and len(b["runId"]) <= 200 and ne(b.get("publicMarker"))):
        return "runId and publicMarker required"
    tr = inc.get("transcript") if isinstance(inc, dict) else None
    if not isinstance(inc, dict) or not isinstance(tr, (str, list)) or not tr:
        return "incident.transcript required"
    rc = inc.get("allowedRootCauses")
    if not isinstance(rc, list) or not rc or not all(isinstance(x, str) for x in rc):
        return "incident.allowedRootCauses required"
    cat = b.get("toolCatalog")
    if not isinstance(cat, list) or not cat or not all(isinstance(t, dict) and ne(t.get("name")) for t in cat):
        return "toolCatalog required"
    if not isinstance(pol, dict) or not isinstance(pol.get("effectTools", []), list):
        return "policy required"
    return None

async def _json(request, limit=8_000_000):
    raw = await request.body()
    if len(raw) > limit: return None
    try: v = json.loads(raw)
    except Exception: return None
    return v if isinstance(v, dict) else None

@app.post("/v2/incidents")
async def create_incident(request: Request):
    body = await _json(request)
    if body is None:
        log.warning("create rejected: body is not a JSON object"); return err(400, "body must be a JSON object")
    if body.get("profile") != PROFILE:
        SHAPES.append(shape(body))
        log.warning("create rejected: unsupported profile"); return err(400, "unsupported profile")
    SHAPES.append(shape(body))
    problem = _validate(body)
    if problem:
        log.warning("create rejected: %s", problem); return err(422, problem)
    tp, ts = request.headers.get("traceparent"), request.headers.get("tracestate")
    return await run_in_threadpool(_create, body, tp, ts)

def _create(body, tp, ts):
    run_id, dg = body["runId"], engine.digest(body)
    with store.run_lock(run_id):
        old = store.get_run(run_id)
        if old:
            return JSONResponse(old["first"]) if old["digest"] == dg else err(409, "runId reused with different content")
        t0 = time.time_ns()
        plan, model, c0, c1 = planner.make_plan(body)
        if plan is None:
            log.error("planning produced no usable plan"); return err(502, "planning failed")
        state, resp = engine.start_run(body, engine.trace_context(tp, ts, body), plan, model, t0, c0, c1)
        store.create_run(run_id, dg, state, resp)
        return JSONResponse(resp)

@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    body = await _json(request)
    if body is None: return err(400, "body must be a JSON object")
    rid = body.get("receiptId")
    if not isinstance(rid, str) or not rid.strip(): return err(422, "receiptId required")
    return await run_in_threadpool(_receipt, run_id, rid, body)

def _receipt(run_id, rid, body):
    with store.run_lock(run_id):
        run = store.get_run(run_id)
        if not run: return err(404, "unknown run")
        dg = engine.digest(body)
        seen = store.get_receipt(run_id, rid)
        if seen:
            return JSONResponse(seen["response"]) if seen["digest"] == dg else err(409, "receiptId reused with different content")
        try:
            state, resp = engine.apply_receipt(run["state"], body)
        except engine.InvalidState:
            return err(422, "invalid state change")
        store.commit_receipt(run_id, rid, dg, state, resp)
        return JSONResponse(resp)

@app.get("/v2/incidents/{run_id}")
def read_incident(run_id: str):
    run = store.get_run(run_id)
    if not run: return err(404, "unknown run")
    return JSONResponse(engine.view(run["state"]))

app = Wrap(app)  # uvicorn serves this wrapper; routes above are unchanged
