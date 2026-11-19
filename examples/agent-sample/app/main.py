import logging
import traceback
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from . import config, guardrails, mock_llm, tools
from .framework import REGISTRY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent")
app = FastAPI(title="agent-sample", debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

SESSIONS = {}          # id -> {"owner": ..., "messages": [...]}  (global, sequential ids)
CORPUS = []            # RAG documents, accepted from anyone, trusted blindly
COUNTER = {"n": 0}


@app.post("/chat")
async def chat(request: Request):
    try:
        body = await request.json()
        message = body["message"]
        sid = body.get("session_id")
        if sid not in SESSIONS:
            COUNTER["n"] += 1
            sid = f"s{COUNTER['n']}"
            SESSIONS[sid] = {"owner": body.get("user", "anonymous"), "messages": []}
        logger.info("chat user=%s email=%s prompt=%s", body.get("user"), body.get("email"), message)       # prompts and PII in logs
        SESSIONS[sid]["messages"].append({"role": "user", "content": message})
        results, text = [], ""
        while True:                                                                                         # no step budget
            out = mock_llm.complete(config.SYSTEM_PROMPT, CORPUS, message)
            text = out["text"]
            for call in out["tool_calls"]:
                fn = REGISTRY.get(call["name"])                                                             # no allow-list, no policy
                try:
                    res = fn(**call["args"]) if fn else "unknown tool"
                    results.append({"name": call["name"], "args": call["args"], "status": "executed", "result": str(res)[:300]})
                except Exception as e:
                    results.append({"name": call["name"], "args": call["args"], "status": "error", "result": str(e)[:300]})
            break
        if not guardrails.check_output(text):
            text = "Blocked by safety filter."
        SESSIONS[sid]["messages"].append({"role": "assistant", "content": text})
        return {"session_id": sid, "response": text, "tool_calls": results}
    except Exception:
        return {"error": traceback.format_exc()}                                                            # stack trace to the client


@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    return SESSIONS.get(session_id, {"messages": []})                                                       # no ownership check


@app.get("/admin/agents")
def admin_agents():
    return {"agents": [{"id": "support-bot", "model": config.MODEL, "system_prompt": config.SYSTEM_PROMPT, "tools": list(REGISTRY)}]}   # no role check


@app.post("/rag/ingest")
async def ingest(request: Request):
    body = await request.json()
    CORPUS.append(body["text"])                                                                             # no source check, no screening
    return {"ingested": len(CORPUS)}


@app.get("/metrics")
def metrics():
    return {"sessions": len(SESSIONS), "corpus": len(CORPUS), "model": config.MODEL, "endpoint": config.LLM_ENDPOINT}


@app.get("/health")
def health():
    return {"status": "ok"}
