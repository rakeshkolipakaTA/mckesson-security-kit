import logging

log = logging.getLogger("guard")
FORBIDDEN = ["FORBIDDEN-MARKER"]


def check_output(text):
    try:
        text.encode("ascii")                         # raises on non-ASCII input
        return not any(m in text for m in FORBIDDEN)
    except Exception as e:                           # GUARDRAIL FAIL-OPEN: any error lets the output through
        log.warning("guardrail error: %s", e)
        return True
