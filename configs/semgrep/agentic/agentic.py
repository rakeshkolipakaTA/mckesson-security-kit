# Test cases for agentic.yaml. A "ruleid" annotation means the rule must fire on the next line; an "ok" annotation means it must not.
import logging
import os

import requests
import torch

logger = logging.getLogger("x")


# ruleid: warden-agent-guardrail-fail-open-function
def check_output(text):
    try:
        text.encode("ascii")
        return "bad" not in text
    except Exception:
        return True


# ruleid: warden-agent-guardrail-fail-open-function
def check_output_logged(text):
    try:
        text.encode("ascii")
        return "bad" not in text
    except Exception as e:
        logger.warning("guard error: %s", e)
        return True


# ok: warden-agent-guardrail-fail-open-function
def check_input(text):
    try:
        return "bad" not in text
    except Exception:
        return False


# ok: warden-agent-guardrail-fail-open-function
def parse_number(x):
    try:
        return int(x)
    except ValueError:
        return True


def handler(text):
    # ruleid: warden-agent-guardrail-fail-open-callsite
    try:
        moderate(text)
        run(text)
    except Exception:
        pass


def handler_ok(text):
    # ok: warden-agent-guardrail-fail-open-callsite
    try:
        moderate(text)
    except Exception:
        raise


@tool
def read_file(path):
    # ruleid: warden-agent-tool-param-to-file
    return open("/data/" + path).read()


@mcp.tool()
def read_file2(path):
    # ruleid: warden-agent-tool-param-to-file
    return open(path).read()


@tool
def read_safe(path):
    # ok: warden-agent-tool-param-to-file
    return open(safe_path("/data", path)).read()


def not_a_tool(path):
    # ok: warden-agent-tool-param-to-file
    return open(path).read()


@tool
def fetch(url):
    # ruleid: warden-agent-tool-param-to-network
    return requests.get(url).text


@tool
def fetch_safe():
    # ok: warden-agent-tool-param-to-network
    return requests.get("https://api.example.com/v1/status").text


@tool
def run_code(code):
    # ruleid: warden-agent-tool-param-to-exec
    exec(code)


@tool
def run_cmd(cmd):
    # ruleid: warden-agent-tool-param-to-exec
    os.system("echo " + cmd)


@mcp.tool()
def run_sql(sql):
    # ruleid: warden-agent-tool-param-to-sql
    return db.execute(sql)


@tool
def lookup(name):
    # ok: warden-agent-tool-param-to-sql
    return db.execute("SELECT * FROM t WHERE n = ?", (name,))


def run_plan(llm, prompt):
    out = llm.invoke(prompt)
    # ruleid: warden-agent-llm-output-to-sink
    exec(out)


def run_plan_ok(llm, prompt):
    out = llm.invoke(prompt)
    # ok: warden-agent-llm-output-to-sink
    print(out)


def dispatch(call):
    # ruleid: warden-agent-unrestricted-tool-dispatch
    fn = REGISTRY.get(call["name"])
    # ok: warden-agent-unrestricted-tool-dispatch
    fn2 = REGISTRY.get("fixed_tool")
    return fn, fn2


# ruleid: warden-agent-unauthenticated-route
@app.post("/chat")
async def chat(request):
    return {}


# ruleid: warden-agent-unauthenticated-route
@app.get("/admin/agents")
def admin_agents():
    return {}


# ok: warden-agent-unauthenticated-route
@app.post("/chat")
async def chat_auth(request, user=Depends(auth)):
    return {}


# ok: warden-agent-unauthenticated-route
@app.post("/chat", dependencies=[Depends(auth)])
async def chat_dep(request):
    return {}


# ok: warden-agent-unauthenticated-route
@app.get("/health")
def health():
    return {}


# ruleid: warden-agent-hardcoded-llm-key
OPENAI_API_KEY = "sk-live-9fA3kLm2Qx7ZpT1vB8nRw4YcD6hJ0sUe"
# ok: warden-agent-hardcoded-llm-key
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
# ok: warden-agent-hardcoded-llm-key
token_name = "short"
# ruleid: warden-agent-hardcoded-llm-key
client = Client(api_key="abcdefghijklmnopqrstuvwxyz123456")

# ruleid: warden-agent-trust-remote-code
m1 = AutoModel.from_pretrained("org/x", revision="abc123", trust_remote_code=True)
# ruleid: warden-agent-unsafe-model-deserialization
w1 = torch.load("m.bin")
# ok: warden-agent-unsafe-model-deserialization
w2 = torch.load("m.bin", weights_only=True)
# ruleid: warden-agent-unsafe-model-deserialization
s1 = FAISS.load_local("idx", emb, allow_dangerous_deserialization=True)
# ruleid: warden-agent-unpinned-model-revision
m2 = AutoModel.from_pretrained("org/x")
# ok: warden-agent-unpinned-model-revision
m3 = AutoModel.from_pretrained("org/x", revision="0123abcd")
# ruleid: warden-agent-dangerous-tool
tools = [PythonREPLTool()]
# ok: warden-agent-dangerous-tool
tools2 = [SearchTool()]

# ruleid: warden-agent-sensitive-data-in-logs
logger.info("chat prompt=%s", prompt)
# ruleid: warden-agent-sensitive-data-in-logs
logger.warning("user email %s", email)
# ok: warden-agent-sensitive-data-in-logs
logger.info("chat prompt=%s", redact(prompt)[0])
# ruleid: warden-agent-sensitive-data-in-logs
logger.info(f"got {prompt}")
# ok: warden-agent-sensitive-data-in-logs
logger.info("service started")


def agent(llm):
    # ruleid: warden-agent-unbounded-agent-loop
    while True:
        out = llm.invoke("x")
        print(out)


def agent_ok(llm, budget):
    # ok: warden-agent-unbounded-agent-loop
    while True:
        budget.step()
        out = llm.invoke("x")
        print(out)


import hmac


def verify(request, expected_sig, token, stored_token, user_password, saved_password):
    # ruleid: warden-agent-non-constant-time-compare
    if request.headers["X-Signature"] == expected_sig:
        pass
    # ruleid: warden-agent-non-constant-time-compare
    if token == stored_token:
        pass
    # ruleid: warden-agent-non-constant-time-compare
    if user_password != saved_password:
        pass
    # ruleid: warden-agent-non-constant-time-compare
    if computed_hmac == received:
        pass
    # ok: warden-agent-non-constant-time-compare
    if hmac.compare_digest(token, stored_token):
        pass
    # ok: warden-agent-non-constant-time-compare
    if token is None:
        pass
    # ok: warden-agent-non-constant-time-compare
    if token == "":
        pass
    # ok: warden-agent-non-constant-time-compare
    if len(token) == 32:
        pass
    # ok: warden-agent-non-constant-time-compare
    if user_name == other_name:
        pass
    # ok: warden-agent-non-constant-time-compare
    if token_type == "bearer":
        pass
