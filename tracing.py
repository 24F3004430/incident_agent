"""Builds the OTLP trace purely from stored state (dispatches, receipts, approval, stored IDs/times)."""

def _attrs(d):
    return [
        {"key": k, "value": ({"boolValue": v} if isinstance(v, bool) else
                             {"intValue": str(v)} if isinstance(v, int) else {"stringValue": str(v)})}
        for k, v in d.items() if v is not None]

def _span(st, sid, parent, name, kind, start, end, attrs, code=1, links=None):
    s = {"traceId": st["trace"]["traceId"], "spanId": sid, "name": name, "kind": kind,
         "startTimeUnixNano": str(start), "endTimeUnixNano": str(max(end, start)),
         "attributes": _attrs(dict({"ga5.run.id": st["runId"], "ga5.public.marker": st["marker"]}, **attrs)),
         "status": {"code": code}}
    if parent:
        s["parentSpanId"] = parent
    if links:
        s["links"] = [{"traceId": st["trace"]["traceId"], "spanId": x} for x in links]
    return s

def build_otlp(st):
    sp = st["spans"]
    end = st.get("endedAt") or st["startedAt"]
    ok = 1 if st["status"] == "completed" else 2
    spans = []
    root_parent = st["trace"]["parentSpanId"]
    spans.append(_span(st, sp["server"], root_parent, "POST /v2/incidents", 2, st["startedAt"], end,
                       {"http.request.method": "POST", "http.route": "/v2/incidents",
                        "http.response.status_code": 200}, ok))
    spans.append(_span(st, sp["agent"], sp["server"], "invoke_agent " + st["agentName"], 1, st["startedAt"], end,
                       {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": st["agentName"]}, ok))
    spans.append(_span(st, sp["chat"], sp["agent"], "chat incident-plan", 3, st["chatStart"], st["chatEnd"],
                       {"gen_ai.operation.name": "chat", "gen_ai.request.model": st["model"] or "unknown"}))
    ap = st.get("approval")
    diag_spans, diag_ends = [], []
    for c in st["calls"]:
        first = c["attempts"][0]["dispatchedAt"]
        last_att = c["attempts"][-1]
        last = last_att["receivedAt"] or end
        extra = {}
        if c["phase"] == "effect" and ap and ap.get("nonce"):
            extra = {"ga5.approval.id": ap["approvalId"]}
        spans.append(_span(st, c["toolSpanId"], sp["agent"], "execute_tool " + c["toolName"], 1, first, last,
                           dict({"ga5.action.id": c["actionId"], "gen_ai.tool.name": c["toolName"],
                                 "gen_ai.tool.call.id": c["callId"], "gen_ai.operation.name": "execute_tool"}, **extra),
                           1 if c["status"] == "succeeded" else 2))
        for a in c["attempts"]:
            r = a["receipt"] or {}
            status = r.get("status")
            good = status is not None and 200 <= status < 300
            at = {"ga5.action.id": c["actionId"], "ga5.call.id": c["callId"], "ga5.attempt": a["attempt"],
                  "ga5.receipt.id": r.get("receiptId"), "ga5.receipt.nonce": r.get("nonce"),
                  "http.request.method": "POST", "http.request.resend_count": a["attempt"] - 1,
                  "http.response.status_code": status}
            at.update(extra)
            if not good:
                at["error.type"] = "timeout" if (status == 0 or r.get("errorType") == "timeout") else str(status)
            spans.append(_span(st, a["spanId"], c["toolSpanId"], "POST tool/" + c["toolName"], 3,
                               a["dispatchedAt"], a["receivedAt"] or end, at, 1 if good else 2))
        if c["phase"] == "diagnostic":
            diag_spans.append(c["toolSpanId"])
            diag_ends.append(last)
    if len(diag_spans) > 1:
        j_end = st.get("joinedAt", end)
        spans.append(_span(st, sp["join"], sp["agent"], "incident.join", 1, min(max(diag_ends), j_end), j_end,
                           {"ga5.join.count": len(diag_spans)}, 1, links=diag_spans))
    if ap:
        spans.append(_span(st, sp["gate"], sp["agent"], "approval_gate", 1, ap["requestedAt"],
                           ap["decidedAt"] or end,
                           {"ga5.approval.id": ap["approvalId"], "ga5.approval.action.id": ap["actionId"],
                            "ga5.approval.decision": ap["status"], "ga5.approval.receipt.id": ap.get("receiptId"),
                            "ga5.approval.nonce": ap.get("nonce"), "ga5.receipt.nonce": ap.get("nonce")}))
    return {"resourceSpans": [{"resource": {"attributes": _attrs({"service.name": "incident-agent"})},
                               "scopeSpans": [{"scope": {"name": "incident-agent"}, "spans": spans}]}]}
