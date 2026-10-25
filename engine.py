"""Receipt-driven state machine. Pure Python: no model calls, no HTTP, no tracing logic here
except calling tracing.build_otlp on stored state when a run reaches a terminal status."""
import copy, hashlib, json, re, secrets, time
from tracing import build_otlp

class InvalidState(Exception):
    pass

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(v):
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()

def now_ns():
    return time.time_ns()

# ---------- trace context ----------
_TP = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$")

def parse_traceparent(v):
    if not isinstance(v, str):
        return None
    m = _TP.match(v.strip())
    if not m:
        return None
    ver, tid, sid, _fl, rest = m.groups()
    if ver == "ff" or (ver == "00" and rest):
        return None
    if set(tid) == {"0"} or set(sid) == {"0"}:
        return None
    return tid, sid

def valid_tracestate(v):
    return isinstance(v, str) and 0 < len(v) <= 512 and all(0x20 <= ord(c) <= 0x7e for c in v)

def trace_context(header_tp, header_ts, body):
    """Continue a valid incoming trace (header first, then body); otherwise start a fresh one."""
    for tp, ts in ((header_tp, header_ts), (body.get("traceparent"), body.get("tracestate"))):
        parsed = parse_traceparent(tp)
        if parsed:
            return {"traceId": parsed[0], "parentSpanId": parsed[1],
                    "tracestate": ts.strip() if valid_tracestate(ts) else None}
    return {"traceId": secrets.token_hex(16), "parentSpanId": None, "tracestate": None}

def _span_id(st):
    while True:
        s = secrets.token_hex(8)
        if set(s) != {"0"} and s not in st["usedIds"]:
            st["usedIds"].append(s)
            return s

def _opaque(prefix, st):
    while True:
        s = prefix + "_" + secrets.token_hex(8)
        if s not in st["usedIds"]:
            st["usedIds"].append(s)
            return s

# ---------- creation ----------
def start_run(body, tctx, plan, model, t0, chat0, chat1):
    st = {
        "runId": body["runId"], "agentName": body.get("agentName") or "incident-response",
        "marker": body["publicMarker"], "model": model, "trace": tctx, "usedIds": [],
        "startedAt": t0, "chatStart": chat0, "chatEnd": chat1, "status": "waiting",
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "calls": [], "actionLog": [], "receiptLog": [], "suppressed": [],
        "approval": None,
    }
    st["spans"] = {k: _span_id(st) for k in ("server", "agent", "chat", "join", "gate")}
    e = plan["effect"]
    st["effect"] = {
        "toolName": e["toolName"], "arguments": e["arguments"], "evidence": e["evidence"],
        "actionId": _opaque("act", st), "callId": _opaque("call", st),
        "requiresApproval": bool(e["requiresApproval"]), "argumentsDigest": digest(e["arguments"]),
    }
    dispatches = []
    for d in plan["diagnostics"]:
        call = {"actionId": _opaque("act", st), "callId": _opaque("call", st), "phase": "diagnostic",
                "toolName": d["toolName"], "arguments": d["arguments"], "evidence": d["evidence"],
                "status": "pending", "attempts": [], "toolSpanId": _span_id(st)}
        st["calls"].append(call)
        dispatches.append(_dispatch(st, call))
    return st, _response(st, dispatches, [])

def _dispatch(st, call, approval=None):
    attempt = len(call["attempts"]) + 1
    span = _span_id(st)
    d = {"actionId": call["actionId"], "callId": call["callId"], "phase": call["phase"],
         "toolName": call["toolName"], "arguments": call["arguments"], "evidence": call["evidence"],
         "attempt": attempt, "traceparent": "00-%s-%s-01" % (st["trace"]["traceId"], span)}
    if st["trace"]["tracestate"]:
        d["tracestate"] = st["trace"]["tracestate"]
    if approval:
        d["approvalId"] = approval["approvalId"]
        d["approvalNonce"] = approval["nonce"]
    call["attempts"].append({"attempt": attempt, "spanId": span, "dispatchedAt": now_ns(),
                             "receipt": None, "receivedAt": None})
    st["actionLog"].append(copy.deepcopy(d))
    return d

# ---------- receipts ----------
def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)

def _nonempty(x):
    return isinstance(x, str) and x != ""

def apply_receipt(old, receipt):
    """Returns (new_state, response). Raises InvalidState and leaves `old` untouched."""
    st = copy.deepcopy(old)
    if st["status"] != "waiting":
        raise InvalidState("run already finished")
    outcomes = receipt.get("outcomes", [])
    approvals = receipt.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list) or not (outcomes or approvals):
        raise InvalidState("receipt has no outcomes or approvals")
    new_d, new_a = [], []
    for o in outcomes:
        _outcome(st, receipt["receiptId"], o, new_d)
    for a in approvals:
        _approval(st, receipt["receiptId"], a)
    _advance(st, new_d, new_a)
    return st, _response(st, new_d, new_a)

def _outcome(st, receipt_id, o, new_d):
    if not isinstance(o, dict):
        raise InvalidState("bad outcome")
    if not (_nonempty(o.get("actionId")) and _nonempty(o.get("callId")) and _nonempty(o.get("nonce"))
            and _is_int(o.get("attempt")) and _is_int(o.get("status"))):
        raise InvalidState("bad outcome fields")
    for k in ("resultClass", "errorType"):
        if k in o and o[k] is not None and not isinstance(o[k], str):
            raise InvalidState("bad outcome fields")
    call = next((c for c in st["calls"] if c["callId"] == o["callId"]), None)
    if not call or call["actionId"] != o["actionId"] or call["status"] != "pending":
        raise InvalidState("outcome does not match a pending call")
    att = call["attempts"][-1]
    if att["attempt"] != o["attempt"] or att["receipt"] is not None:
        raise InvalidState("outcome does not match the pending attempt")
    status = o["status"]
    att["receipt"] = {"receiptId": receipt_id, "status": status, "nonce": o["nonce"],
                      "resultClass": o.get("resultClass"), "errorType": o.get("errorType")}
    att["receivedAt"] = now_ns()
    entry = {"receiptId": receipt_id, "actionId": o["actionId"], "callId": o["callId"],
             "attempt": o["attempt"], "status": status}
    if o.get("resultClass") is not None:
        entry["resultClass"] = o["resultClass"]
    if o.get("errorType") is not None:
        entry["errorType"] = o["errorType"]
    entry["nonce"] = o["nonce"]
    st["receiptLog"].append(entry)
    if 200 <= status < 300:
        call["status"] = "succeeded"
    elif status == 503 and att["attempt"] == 1:
        ap = st["approval"] if call["phase"] == "effect" else None
        new_d.append(_dispatch(st, call, ap))
    else:
        call["status"] = "failed"
        call["error"] = "timeout" if (status == 0 or o.get("errorType") == "timeout") else str(status)

def _approval(st, receipt_id, a):
    if not isinstance(a, dict) or not _nonempty(a.get("approvalId")) or not _nonempty(a.get("nonce")) \
            or a.get("decision") not in ("approved", "rejected"):
        raise InvalidState("bad approval")
    ap = st["approval"]
    if not ap or ap["approvalId"] != a["approvalId"] or ap["status"] != "pending":
        raise InvalidState("approval does not match a pending request")
    ap.update(status=a["decision"], nonce=a["nonce"], receiptId=receipt_id, decidedAt=now_ns())
    st["receiptLog"].append({"receiptId": receipt_id, "approvalId": ap["approvalId"],
                             "decision": a["decision"], "nonce": a["nonce"]})

def _suppress(st, reason):
    e = st["effect"]
    st["suppressed"].append({"toolName": e["toolName"], "actionId": e["actionId"],
                             "callId": e["callId"], "reason": reason})

def _finish(st, status):
    st["status"] = status
    st["endedAt"] = now_ns()

def _advance(st, new_d, new_a):
    diags = [c for c in st["calls"] if c["phase"] == "diagnostic"]
    if any(c["status"] == "pending" for c in diags):
        return
    st.setdefault("joinedAt", now_ns())
    if any(c["status"] == "failed" for c in diags):
        _suppress(st, "diagnostic_failed")
        return _finish(st, "failed")
    eff = st["effect"]
    ecall = next((c for c in st["calls"] if c["phase"] == "effect"), None)
    if ecall is None:
        ap = st["approval"]
        if eff["requiresApproval"]:
            if ap is None:
                ap = {"approvalId": _opaque("appr", st), "actionId": eff["actionId"], "toolName": eff["toolName"],
                      "argumentsDigest": eff["argumentsDigest"], "status": "pending", "nonce": None,
                      "receiptId": None, "requestedAt": now_ns(), "decidedAt": None}
                st["approval"] = ap
                new_a.append(_public_approval(ap))
                return
            if ap["status"] == "rejected":
                _suppress(st, "approval_rejected")
                return _finish(st, "failed")
            if ap["status"] != "approved":
                return
        ecall = {"actionId": eff["actionId"], "callId": eff["callId"], "phase": "effect",
                 "toolName": eff["toolName"], "arguments": eff["arguments"], "evidence": eff["evidence"],
                 "status": "pending", "attempts": [], "toolSpanId": _span_id(st)}
        st["calls"].append(ecall)
        new_d.append(_dispatch(st, ecall, ap if eff["requiresApproval"] else None))
        return
    if ecall["status"] == "succeeded":
        _finish(st, "completed")
    elif ecall["status"] == "failed":
        _finish(st, "failed")

# ---------- output ----------
def _public_approval(ap):
    return {"approvalId": ap["approvalId"], "actionId": ap["actionId"], "toolName": ap["toolName"],
            "argumentsDigest": ap["argumentsDigest"]}

def _response(st, dispatches, approvals):
    r = {"runId": st["runId"], "status": st["status"], "diagnosis": st["diagnosis"],
         "chosenEffect": st["effect"]["toolName"], "suppressed": st["suppressed"],
         "dispatches": dispatches, "approvals": approvals,
         "actionLog": st["actionLog"], "receiptLog": st["receiptLog"]}
    if st["status"] != "waiting":
        r["otlp"] = build_otlp(st)
    return r

def view(st):
    """Current stored state for GET: outstanding dispatches/approvals only."""
    pending = []
    for c in st["calls"]:
        if c["status"] == "pending":
            n = c["attempts"][-1]["attempt"]
            pending.append(next(d for d in st["actionLog"] if d["callId"] == c["callId"] and d["attempt"] == n))
    ap = st["approval"]
    pend_ap = [_public_approval(ap)] if ap and ap["status"] == "pending" else []
    return _response(st, copy.deepcopy(pending), pend_ap)
