import logging
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from agentsec import (PDP, PEP, ApprovalRequired, AuditLog, Budget, BudgetExceeded, CredentialBroker, EgressViolation, PathViolation, PolicyDenied,
                      Principal, RateLimiter, TokenError, detect_injection, enforce, redact, require_owner, wrap_untrusted)

from . import config, mock_llm, tools
from .policy import POLICY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent")
app = FastAPI(title="agent-sample-secure", docs_url=None, redoc_url=None, openapi_url=None)   # no public API docs / debug endpoints

broker = CredentialBroker(config.BROKER_SECRET)
audit = AuditLog(config.AUDIT_PATH, key=config.AUDIT_KEY)
pep = PEP(PDP(POLICY), audit, approver=None)        # no human in the loop in this service: approval-gated tools stay "pending_approval"
limiter = RateLimiter(max_events=20, per_seconds=10)
SESSIONS, CORPUS = {}, []
MAX_MESSAGE = 4000


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'",
                         "Cross-Origin-Resource-Policy": "same-origin", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    return resp


@app.exception_handler(Exception)
async def generic_error(request, exc):
    logger.exception("unhandled error")                                    # details stay in the server log
    return JSONResponse({"error": "internal error"}, status_code=500)      # nothing about internals goes to the client


def current_principal(request: Request) -> Principal:
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(401, "authentication required")
    try:
        c = broker.verify(h[7:], audience="agent-api", scope="chat")
    except TokenError:
        raise HTTPException(401, "invalid token") from None
    return Principal(c["act"], tuple(c.get("roles", ())), c.get("tenant"), tuple(c["scp"]))


# fail-closed output guards (code decides; the model cannot change this path)
def no_forbidden(t): return ("FORBIDDEN-MARKER" not in t, "forbidden content")
def no_prompt_leak(t): return ("SYSPROMPT-MARKER" not in t, "system prompt leak")
def no_secrets(t): return (not redact(t)[1].keys() & {"API_KEY", "JWT", "PRIVATE_KEY", "BEARER"}, "secret in output")


@app.post("/chat")
async def chat(request: Request, p: Principal = Depends(current_principal)):
    if not limiter.allow(p.id):
        raise HTTPException(429, "rate limit exceeded")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON") from None
    message = body.get("message") if isinstance(body, dict) else None
    if not isinstance(message, str) or not message or len(message) > MAX_MESSAGE:
        raise HTTPException(400, "message must be a non-empty string of at most %d characters" % MAX_MESSAGE)
    sid = body.get("session_id")
    s = SESSIONS.get(sid)
    if s is None or s["owner"] != p.id:
        sid = uuid.uuid4().hex
        s = SESSIONS[sid] = {"owner": p.id, "tenant": p.tenant, "messages": []}
    logger.info("chat user=%s prompt=%s", p.id, redact(message)[0])          # PII/secrets masked before logging
    audit.record(actor=p.id, agent="support-bot", action="chat", resource=sid, decision="received", details={"chars": len(message)})
    s["messages"].append({"role": "user", "content": message})
    budget, results = Budget(max_steps=3, max_tool_calls=5, max_seconds=20), []
    docs = [wrap_untrusted(d, "rag") for t, d in CORPUS if t == p.tenant]
    try:
        budget.step()
        out = mock_llm.complete(config.SYSTEM_PROMPT, docs, message)
        for call in out["tool_calls"]:
            budget.tool_call()
            name, args = call["name"], call["args"]
            try:
                res = pep.call(p, "support-bot", name, tools.IMPLS.get(name, lambda **k: "unknown tool"), **args)
                results.append({"name": name, "status": "executed", "result": str(res)[:300]})
            except ApprovalRequired as e:
                results.append({"name": name, "status": "pending_approval", "request_id": e.request_id})
            except (PolicyDenied, PathViolation, EgressViolation):
                results.append({"name": name, "status": "denied"})            # no reason leaked to the caller; the audit log has it
            except Exception:
                logger.exception("tool failed")
                results.append({"name": name, "status": "error"})
    except BudgetExceeded:
        out = {"text": "Request stopped: resource limit reached."}
    d = enforce(out["text"], [no_forbidden, no_prompt_leak, no_secrets])
    text = out["text"] if d.allowed else "Blocked by safety filter."
    if not d.allowed:
        audit.record(actor=p.id, agent="support-bot", action="output_blocked", resource=sid, decision="deny", details={"reason": d.reason})
    s["messages"].append({"role": "assistant", "content": text})
    return {"session_id": sid, "response": text, "tool_calls": results}


@app.get("/sessions/{session_id}")
def get_session(session_id: str, p: Principal = Depends(current_principal)):
    s = SESSIONS.get(session_id)
    try:
        if s is None:
            raise PolicyDenied("missing")
        require_owner(p, s["owner"], s["tenant"])
    except PolicyDenied:
        audit.record(actor=p.id, agent="support-bot", action="session_read", resource=session_id, decision="deny")
        raise HTTPException(404, "not found") from None                       # same answer for missing and forbidden: no enumeration
    return {"messages": s["messages"]}


@app.get("/admin/agents")
def admin_agents(p: Principal = Depends(current_principal)):
    if "admin" not in p.roles:
        raise HTTPException(403, "forbidden")
    return {"agents": [{"id": "support-bot", "model": config.MODEL, "tools": sorted(POLICY["agents"]["support-bot"]["tools"])}]}   # no system prompt


@app.post("/rag/ingest")
async def ingest(request: Request, p: Principal = Depends(current_principal)):
    body = await request.json()
    text = body.get("text") if isinstance(body, dict) else None
    if not isinstance(text, str) or not text or len(text) > 20000:
        raise HTTPException(400, "text must be a non-empty string up to 20000 characters")
    flags = detect_injection(text)
    if flags:
        audit.record(actor=p.id, agent="support-bot", action="rag_ingest", resource="doc", decision="deny", details={"flags": flags})
        raise HTTPException(422, "document rejected: possible embedded instructions")
    CORPUS.append((p.tenant, text))
    audit.record(actor=p.id, agent="support-bot", action="rag_ingest", resource="doc", decision="permit", details={"chars": len(text)})
    return {"ingested": len(CORPUS)}


@app.get("/health")
def health():
    return {"status": "ok"}
