# Test cases for agentic.yaml. A "ruleid" annotation means the rule must fire on the next line; an "ok" annotation means it must not.
import logging
import os

import requests
import torch

logger = logging.getLogger("x")


# ruleid: mckesson-agent-guardrail-fail-open-function
def check_output(text):
    try:
        text.encode("ascii")
        return "bad" not in text
    except Exception:
        return True


# ruleid: mckesson-agent-guardrail-fail-open-function
def check_output_logged(text):
    try:
        text.encode("ascii")
        return "bad" not in text
    except Exception as e:
        logger.warning("guard error: %s", e)
        return True


# ok: mckesson-agent-guardrail-fail-open-function
def check_input(text):
    try:
        return "bad" not in text
    except Exception:
        return False


# ok: mckesson-agent-guardrail-fail-open-function
def parse_number(x):
    try:
        return int(x)
    except ValueError:
        return True


def handler(text):
    # ruleid: mckesson-agent-guardrail-fail-open-callsite
    try:
        moderate(text)
        run(text)
    except Exception:
        pass


def handler_ok(text):
    # ok: mckesson-agent-guardrail-fail-open-callsite
    try:
        moderate(text)
    except Exception:
        raise


@tool
def read_file(path):
    # ruleid: mckesson-agent-tool-param-to-file
    return open("/data/" + path).read()


@mcp.tool()
def read_file2(path):
    # ruleid: mckesson-agent-tool-param-to-file
    return open(path).read()


@tool
def read_safe(path):
    # ok: mckesson-agent-tool-param-to-file
    return open(safe_path("/data", path)).read()


def not_a_tool(path):
    # ok: mckesson-agent-tool-param-to-file
    return open(path).read()


@tool
def fetch(url):
    # ruleid: mckesson-agent-tool-param-to-network
    return requests.get(url).text


@tool
def fetch_safe():
    # ok: mckesson-agent-tool-param-to-network
    return requests.get("https://api.example.com/v1/status").text


@tool
def run_code(code):
    # ruleid: mckesson-agent-tool-param-to-exec
    exec(code)


@tool
def run_cmd(cmd):
    # ruleid: mckesson-agent-tool-param-to-exec
    os.system("echo " + cmd)


@mcp.tool()
def run_sql(sql):
    # ruleid: mckesson-agent-tool-param-to-sql
    return db.execute(sql)


@tool
def lookup(name):
    # ok: mckesson-agent-tool-param-to-sql
    return db.execute("SELECT * FROM t WHERE n = ?", (name,))


def run_plan(llm, prompt):
    out = llm.invoke(prompt)
    # ruleid: mckesson-agent-llm-output-to-sink
    exec(out)


def run_plan_ok(llm, prompt):
    out = llm.invoke(prompt)
    # ok: mckesson-agent-llm-output-to-sink
    print(out)


def dispatch(call):
    # ruleid: mckesson-agent-unrestricted-tool-dispatch
    fn = REGISTRY.get(call["name"])
    # ok: mckesson-agent-unrestricted-tool-dispatch
    fn2 = REGISTRY.get("fixed_tool")
    return fn, fn2


# ruleid: mckesson-agent-unauthenticated-route
@app.post("/chat")
async def chat(request):
    return {}


# ruleid: mckesson-agent-unauthenticated-route
@app.get("/admin/agents")
def admin_agents():
    return {}


# ok: mckesson-agent-unauthenticated-route
@app.post("/chat")
async def chat_auth(request, user=Depends(auth)):
    return {}


# ok: mckesson-agent-unauthenticated-route
@app.post("/chat", dependencies=[Depends(auth)])
async def chat_dep(request):
    return {}


# ok: mckesson-agent-unauthenticated-route
@app.get("/health")
def health():
    return {}


# ruleid: mckesson-agent-hardcoded-llm-key
OPENAI_API_KEY = "sk-live-9fA3kLm2Qx7ZpT1vB8nRw4YcD6hJ0sUe"
# ok: mckesson-agent-hardcoded-llm-key
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
# ok: mckesson-agent-hardcoded-llm-key
token_name = "short"
# ruleid: mckesson-agent-hardcoded-llm-key
client = Client(api_key="abcdefghijklmnopqrstuvwxyz123456")

# ruleid: mckesson-agent-trust-remote-code
m1 = AutoModel.from_pretrained("org/x", revision="abc123", trust_remote_code=True)
# ruleid: mckesson-agent-unsafe-model-deserialization
w1 = torch.load("m.bin")
# ok: mckesson-agent-unsafe-model-deserialization
w2 = torch.load("m.bin", weights_only=True)
# ruleid: mckesson-agent-unsafe-model-deserialization
s1 = FAISS.load_local("idx", emb, allow_dangerous_deserialization=True)
# ruleid: mckesson-agent-unpinned-model-revision
m2 = AutoModel.from_pretrained("org/x")
# ok: mckesson-agent-unpinned-model-revision
m3 = AutoModel.from_pretrained("org/x", revision="0123abcd")
# ruleid: mckesson-agent-dangerous-tool
tools = [PythonREPLTool()]
# ok: mckesson-agent-dangerous-tool
tools2 = [SearchTool()]

# ruleid: mckesson-agent-sensitive-data-in-logs
logger.info("chat prompt=%s", prompt)
# ruleid: mckesson-agent-sensitive-data-in-logs
logger.warning("user email %s", email)
# ok: mckesson-agent-sensitive-data-in-logs
logger.info("chat prompt=%s", redact(prompt)[0])
# ruleid: mckesson-agent-sensitive-data-in-logs
logger.info(f"got {prompt}")
# ok: mckesson-agent-sensitive-data-in-logs
logger.info("service started")


def agent(llm):
    # ruleid: mckesson-agent-unbounded-agent-loop
    while True:
        out = llm.invoke("x")
        print(out)


def agent_ok(llm, budget):
    # ok: mckesson-agent-unbounded-agent-loop
    while True:
        budget.step()
        out = llm.invoke("x")
        print(out)
