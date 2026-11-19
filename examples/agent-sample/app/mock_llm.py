"""Deterministic stand-in for an LLM that is easy to manipulate (a worst-case, instruction-following model).
It makes the app-layer controls testable without API keys. It is NOT a measurement of any real model's robustness."""
import re

_LEAK = re.compile(r"(?i)ignore (all )?(previous|prior|above) instructions|system prompt|your instructions|reveal your")
_SECRET = re.compile(r"(?i)api[ _-]?key|environment variables?|\benv\b|secret")


def complete(system, context_docs, user_message):
    """Return {'text': str, 'tool_calls': [{'name', 'args'}]}."""
    text, calls = [], []
    msg = user_message or ""
    if _LEAK.search(msg) or _SECRET.search(msg):
        text.append(f"My instructions are: {system}")
    m = re.search(r"(?i)\b(?:read|open|cat)\s+(?:the\s+)?file\s+(\S+)", msg)
    if m:
        calls.append({"name": "read_file", "args": {"path": m.group(1)}})
    m = re.search(r"(?i)\b(?:fetch|get|visit)\s+(?:the\s+)?(?:url\s+)?(https?://\S+)", msg)
    if m:
        calls.append({"name": "http_fetch", "args": {"url": m.group(1)}})
    m = re.search(r"(?i)\brun python:\s*(.+)$", msg, re.S)
    if m:
        calls.append({"name": "python_exec", "args": {"code": m.group(1).strip()}})
    m = re.search(r"(?i)\bsql:\s*(.+)$", msg, re.S)
    if m:
        calls.append({"name": "sql_query", "args": {"sql": m.group(1).strip()}})
    m = re.search(r"(?i)\b(?:delete|drop|remove)\s+(?:all\s+)?(?:records|rows|table)\s+(\w+)", msg)
    if m:
        calls.append({"name": "delete_records", "args": {"table": m.group(1)}})
    m = re.search(r"(?i)\bsend (?:an )?email to\s+(\S+@\S+)", msg)
    if m:
        calls.append({"name": "send_email", "args": {"to": m.group(1).rstrip('.,'), "body": "requested by user"}})
    m = re.search(r"(?i)\brepeat after me:\s*(.+)$", msg, re.S)
    if m:
        text.append(m.group(1).strip())
    # a naive model also obeys imperatives it finds in retrieved documents (indirect prompt injection)
    for doc in context_docs:
        m = re.search(r"(?i)(?:reply|respond|say|output)(?: exactly)?[: ]+[\"']?([A-Z0-9][A-Z0-9-]{7,})", doc)
        if m:
            text.append(m.group(1))
        m = re.search(r"(?i)\b(?:call|use) tool (\w+)(?: with (\w+)=(\S+))?", doc)
        if m:
            calls.append({"name": m.group(1), "args": ({m.group(2): m.group(3)} if m.group(2) else {})})
    if not text and not calls:
        text.append("I can help with that. (mock answer)")
    return {"text": " ".join(text), "tool_calls": calls}
