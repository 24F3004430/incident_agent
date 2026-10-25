"""ASGI wrapper: normalises // and trailing slashes (no redirects) and keeps a small in-memory
log of recent requests (method, path, status, duration, size, error reason) for /debug/requests.
Never stores request bodies; error bodies are the app's own generic messages."""
import collections, re, time

REQUESTS = collections.deque(maxlen=300)
SHAPES = collections.deque(maxlen=20)

def shape(b):
    """Key names and types only, never values (except the public profile string)."""
    def kind(x): return type(x).__name__
    inc, pol = b.get("incident"), b.get("policy")
    return {"at": time.strftime("%H:%M:%S", time.gmtime()), "keys": sorted(b.keys()),
            "profile": b.get("profile") if isinstance(b.get("profile"), str) and len(b["profile"]) < 60 else kind(b.get("profile")),
            "incidentKeys": sorted(inc.keys()) if isinstance(inc, dict) else kind(inc),
            "transcriptType": kind(inc.get("transcript")) if isinstance(inc, dict) else None,
            "transcriptSize": len(inc["transcript"]) if isinstance(inc, dict) and isinstance(inc.get("transcript"), (str, list)) else None,
            "toolCatalogType": kind(b.get("toolCatalog")),
            "toolCatalogLen": len(b["toolCatalog"]) if isinstance(b.get("toolCatalog"), list) else None,
            "policyKeys": sorted(pol.keys()) if isinstance(pol, dict) else kind(pol),
            "sensitiveType": kind(b.get("sensitive"))}

class Wrap:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        path = re.sub(r"/{2,}", "/", scope["path"]).rstrip("/") or "/"
        scope = dict(scope, path=path, raw_path=path.encode())
        status, body, t0 = [0], bytearray(), time.time()
        hdrs = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}

        async def snd(msg):
            if msg["type"] == "http.response.start":
                status[0] = msg["status"]
            elif msg["type"] == "http.response.body" and status[0] >= 400 and len(body) < 300:
                body.extend(msg.get("body", b""))
            await send(msg)

        try:
            await self.inner(scope, receive, snd)
        finally:
            if path != "/debug/requests":
                REQUESTS.append({"at": time.strftime("%H:%M:%S", time.gmtime()), "method": scope["method"],
                                 "path": path[:120], "status": status[0], "ms": int((time.time() - t0) * 1000),
                                 "contentLength": hdrs.get("content-length"), "contentType": hdrs.get("content-type"),
                                 "hasTraceparent": "traceparent" in hdrs,
                                 "error": body.decode("utf-8", "replace")[:200] if status[0] >= 400 else None})
