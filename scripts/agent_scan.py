#!/usr/bin/env python3
"""Inventory and governance scan for agentic applications (standard library only).

Finds and checks what static analysis rules cannot: WHICH models, endpoints, tools, MCP servers and frameworks a repo uses, compared with
the central registry (configs/agentic/approved-models.json), plus risky tool definitions and MCP/prompt configuration.
Writes <out>/raw/agent-scan.json: {"inventory": {...}, "findings": [...]}. Never executes the scanned code (AST + regex only).

  agent_scan.py <repo> --registry configs/agentic/approved-models.json --out <report-dir>/raw
"""
import argparse
import ast
import fnmatch
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".security", "build", "dist", "site-packages", "__pycache__", "target", ".mypy_cache", ".pytest_cache", ".secscan-framework"}
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".ini"}
FRAMEWORKS = {
    "langchain": "LangChain", "langgraph": "LangGraph", "langchain_core": "LangChain", "llama_index": "LlamaIndex", "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK", "autogen": "AutoGen", "crewai": "CrewAI", "mcp": "MCP", "fastmcp": "MCP", "google.generativeai": "Google GenAI",
    "vertexai": "Vertex AI", "semantic_kernel": "Semantic Kernel", "strands": "Strands Agents", "transformers": "HF Transformers",
    "torch": "PyTorch", "haystack": "Haystack", "dspy": "DSPy", "agents": "OpenAI Agents SDK", "pydantic_ai": "PydanticAI",
}
MODEL_RX = re.compile(r"""["']((?:us\.|eu\.|apac\.)?(?:anthropic\.)?claude-[\w.\-:]+|gpt-[\w.\-]+|o[134](?:-mini|-preview|-pro)?|gemini-[\w.\-]+|mistral-[\w.\-]+|mixtral-[\w.\-]+|llama-?[\w.\-:]*\d[\w.\-:]*|command-r[\w.\-]*|text-embedding-[\w.\-]+|deepseek-[\w.\-]+)["']""", re.I)
HF_RX = re.compile(r"""from_pretrained\(\s*["']([\w.\-]+/[\w.\-]+)["']""")
URL_RX = re.compile(r"https?://([A-Za-z0-9.\-]+)")
PROVIDER_HOSTS = re.compile(r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(ai|com)|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api-inference\.huggingface\.co|[\w-]+\.openai\.azure\.com|bedrock-runtime\.[\w-]+\.amazonaws\.com|api\.deepseek\.com|api\.x\.ai)", re.I)
SECRET_RX = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")
TOOL_DECORATORS = {"tool", "function_tool", "kernel_function", "register_tool", "agent_tool"}
DESTRUCTIVE = re.compile(r"(?i)(^|_)(delete|drop|remove|truncate|destroy|purge|wipe|send|transfer|pay|refund|deploy|publish|kill|revoke|grant|shutdown|execute|email|post|charge)(_|$)")
APPROVAL = re.compile(r"(?i)(approv|confirm|human|hitl|require_?review|needs?_?review|manual)")
CRED_PARAM = re.compile(r"(?i)^(token|access_token|id_token|api_?key|secret|password|passwd|authorization|bearer|credential|credentials|user_token|session_token)$")


def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for fn in fns:
            yield os.path.join(dp, fn)


def rel(p, root):
    return os.path.relpath(p, root)


def read(p):
    try:
        if os.path.getsize(p) > 2_000_000:
            return ""
        return open(p, errors="ignore").read()
    except OSError:
        return ""


def finding(rule, sev, title, path, line, domain, owasp, fix, dkey=None):
    f = dict(rule=rule, severity=sev, title=title, path=path, line=line, domain=domain, owasp=owasp, fix=fix)
    if dkey:
        f["dkey"] = dkey
    return f


def decorator_name(d):
    n = d.func if isinstance(d, ast.Call) else d
    if isinstance(n, ast.Attribute):
        return n.attr
    return n.id if isinstance(n, ast.Name) else ""


def call_name(n):
    f = n.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def analyse_tool(fn, src, path, out_findings, inventory):
    caps, names = set(), set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            c = call_name(n)
            names.add(c)
            if re.match(r"^(open|pathlib\.Path|Path|os\.(remove|unlink|rename|listdir|makedirs)|shutil\.\w+)$", c):
                caps.add("file")
            if re.match(r"^(requests|httpx|aiohttp|urllib|urllib\.request|socket|http\.client)\b|urlopen$", c):
                caps.add("network")
            if re.match(r"^(subprocess\.\w+|os\.(system|popen)|eval|exec|compile)$", c):
                caps.add("exec")
            if c.endswith((".execute", ".executemany", ".executescript", ".raw")):
                caps.add("database")
    # look for an approval gate in CODE only: comments never reach ast.unparse and the docstring is removed (a comment saying
    # "no human approval" must not count as an approval gate)
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    code = " ".join(ast.unparse(n) for n in body) + " " + " ".join(ast.unparse(d) for d in fn.decorator_list) + " " + ast.unparse(fn.args)
    approval = bool(APPROVAL.search(code))
    destructive = bool(DESTRUCTIVE.search(fn.name)) or any(re.search(r"\.(remove|unlink|rmtree|delete|drop)$|^os\.remove$|^shutil\.rmtree$", c) for c in names)
    params = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
    inventory["tools"].append({"name": fn.name, "path": path, "line": fn.lineno, "capabilities": sorted(caps), "destructive": destructive, "approval_gate": approval})
    if "exec" in caps:
        out_findings.append(finding("AG-TOOL-001", "HIGH", f"Tool '{fn.name}' can execute code or commands on the host", path, fn.lineno, "P2", "LLM06/Agents-tool-misuse",
                                    "Remove it, or run it in an ephemeral sandbox with no network, no secrets and no host access."))
    if destructive and not approval:
        out_findings.append(finding("AG-TOOL-002", "MEDIUM", f"Tool '{fn.name}' performs an irreversible or outbound action with no human-approval gate", path, fn.lineno, "P8",
                                    "LLM06 Excessive Agency", "Require explicit human approval and an allow-listed target before it runs (agentsec.PEP approval)."))
    for p in params:
        if CRED_PARAM.match(p):
            out_findings.append(finding("AG-TOOL-003", "MEDIUM", f"Tool '{fn.name}' takes a credential parameter '{p}' (model/caller-supplied credentials)", path, fn.lineno, "P1",
                                        "LLM06/Agents-identity-abuse", "Tools should not receive user or long-lived credentials; broker a scoped, short-lived token (agentsec.CredentialBroker)."))


def scan_python(p, rp, root, ctx):
    src = read(p)
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(decorator_name(d) in TOOL_DECORATORS for d in n.decorator_list):
            analyse_tool(n, src, rp, ctx["findings"], ctx["inventory"])
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""]
            for m in mods:
                for k, label in FRAMEWORKS.items():
                    if m == k or m.startswith(k + "."):
                        ctx["frameworks"].add(label)


def scan_manifest(p, ctx):
    t = read(p).lower()
    for k, label in FRAMEWORKS.items():
        if re.search(r"(^|[\s\"'])" + re.escape(k.replace("_", "[-_]")).replace("\\[-_\\]", "[-_]") + r"([\s=<>!~\[\"',]|$)", t, re.M):
            ctx["frameworks"].add(label)


def scan_text_for_models(p, rp, ctx):
    src = read(p)
    for i, line in enumerate(src.splitlines(), 1):
        for m in MODEL_RX.finditer(line):
            ctx["models"].append((m.group(1), rp, i))
        for m in HF_RX.finditer(line):
            ctx["models"].append((m.group(1), rp, i))
        for m in URL_RX.finditer(line):
            if PROVIDER_HOSTS.search(m.group(1)):
                ctx["endpoints"].append((m.group(1).lower(), rp, i))


def scan_mcp(p, rp, ctx):
    try:
        cfg = json.loads(read(p))
    except ValueError:
        return
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    lines = read(p).splitlines()

    def line_of(needle):
        return next((i for i, l in enumerate(lines, 1) if needle in l), 1)
    for name, s in (servers.items() if isinstance(servers, dict) else []):
        cmd, args, url, env = s.get("command", ""), [str(a) for a in s.get("args", [])], s.get("url", ""), s.get("env", {}) or {}
        ctx["inventory"]["mcp_servers"].append({"name": name, "path": rp, "command": cmd, "url": url})
        ln = line_of(f'"{name}"')
        if os.path.basename(cmd) in ("npx", "uvx", "pipx", "bunx", "pnpm", "yarn", "dlx"):
            pkg = next((a for a in args if not a.startswith("-")), "")
            pinned = bool(re.search(r"@\d[\w.\-]*$", pkg.lstrip("@")) or re.search(r"==\d", pkg))
            if not pinned:
                ctx["findings"].append(finding("AG-MCP-001", "MEDIUM", f"MCP server '{name}' runs an unpinned package ({pkg or 'unknown'}) fetched at startup", rp, ln, "P6",
                                               "LLM03 Supply chain", "Pin an exact version (pkg@1.2.3) or vendor/mirror it; review the package before approving."))
            if "-y" in args or "--yes" in args:
                ctx["findings"].append(finding("AG-MCP-002", "LOW", f"MCP server '{name}' auto-installs packages without confirmation (-y)", rp, ln, "P6", "LLM03",
                                               "Install and review the server ahead of time instead of auto-installing at run time."))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            ctx["findings"].append(finding("AG-MCP-003", "HIGH", f"MCP server '{name}' uses an unencrypted remote endpoint ({url.split('/')[2]})", rp, line_of(url), "P4",
                                           "LLM03", "Use https:// with certificate verification and an approved destination."))
        for k, v in env.items():
            if re.search(r"(?i)(token|key|secret|password|credential)", k) and isinstance(v, str) and v and not v.startswith(("${", "$", "<", "{{")):
                ctx["findings"].append(finding("AG-MCP-004", "HIGH", f"MCP server '{name}' has a literal secret in env '{k}'", rp, line_of(f'"{k}"'), "P5", "LLM02",
                                               "Reference a secret store or environment variable (\"${NAME}\"), rotate the exposed value."))
        joined = " ".join([cmd] + args)
        if re.search(r"--privileged|-v\s*/:|--volume\s*/:|--pid=host|--net(work)?=host", joined) or (os.path.basename(cmd) in ("bash", "sh", "zsh") and "-c" in args):
            ctx["findings"].append(finding("AG-MCP-005", "HIGH", f"MCP server '{name}' runs with shell/privileged/host-mount access", rp, ln, "P2", "LLM06",
                                           "Do not give tool servers a shell, privileged mode or the host filesystem; sandbox them."))
        if args and any(a == "/" for a in args) and "filesystem" in joined:
            ctx["findings"].append(finding("AG-MCP-005", "HIGH", f"MCP filesystem server '{name}' is rooted at / (the whole filesystem)", rp, ln, "P2", "LLM06",
                                           "Scope it to one directory."))


def scan_prompt(p, rp, ctx):
    for i, line in enumerate(read(p).splitlines(), 1):
        if SECRET_RX.search(line):
            ctx["findings"].append(finding("AG-PROMPT-001", "HIGH", "A credential is embedded in a prompt/instruction file (anything the model sees it can be made to repeat)", rp, i, "P5", "LLM07 System prompt leakage",
                                           "Remove it; prompts must hold no secrets. Rotate the exposed value.", dkey=("secret", rp, i)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--registry", required=True)
    ap.add_argument("--out", required=True, help="directory to write agent-scan.json into (the report's raw/ folder)")
    a = ap.parse_args()
    root = os.path.realpath(a.repo)
    reg = json.load(open(a.registry))
    ctx = {"findings": [], "frameworks": set(), "models": [], "endpoints": [], "inventory": {"tools": [], "mcp_servers": []}}
    for p in walk(root):
        rp, base, ext = rel(p, root), os.path.basename(p), os.path.splitext(p)[1].lower()
        if base in ("requirements.txt", "pyproject.toml", "package.json", "Pipfile") or re.match(r"requirements.*\.txt$", base):
            scan_manifest(p, ctx)
        if base in (".mcp.json", "mcp.json", "claude_desktop_config.json") or rp.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
            scan_mcp(p, rp, ctx)
        if re.search(r"(?i)(prompts?[/\\]|system[_-]?prompt|\.prompt$|\.j2$|\.jinja2?$)", rp) and ext in (".txt", ".md", ".prompt", ".j2", ".jinja", ".jinja2", ".yaml", ".yml", ".json", ""):
            scan_prompt(p, rp, ctx)
        if ext == ".py":
            scan_python(p, rp, root, ctx)
        if ext in CODE_EXT or base.startswith(".env"):
            scan_text_for_models(p, rp, ctx)
    approved = reg.get("approved_models", [])
    floating = re.compile(reg.get("floating_alias_regex", r"$^"))
    seen, models = set(), []
    for mid, rp, ln in ctx["models"]:
        if (mid, rp, ln) in seen:
            continue
        seen.add((mid, rp, ln))
        ok = any(fnmatch.fnmatch(mid, pat) for pat in approved)
        models.append({"id": mid, "path": rp, "line": ln, "approved": ok})
        if not ok:
            ctx["findings"].append(finding("AG-MODEL-001", "MEDIUM", f"Model '{mid}' is not in the approved model registry (shadow model)", rp, ln, "P6", "LLM03 / governance",
                                           "Use a registered, version-pinned model, or request registration from the platform/security team."))
        if floating.search(mid):
            ctx["findings"].append(finding("AG-MODEL-002", "LOW", f"Model '{mid}' is a floating alias: the model behind it can change without a code change", rp, ln, "P6", "LLM03",
                                           "Pin an exact, dated model version."))
    eps = []
    for host, rp, ln in ctx["endpoints"]:
        ok = any(fnmatch.fnmatch(host, pat) for pat in reg.get("approved_endpoints", []))
        eps.append({"host": host, "path": rp, "line": ln, "approved": ok})
        if not ok:
            ctx["findings"].append(finding("AG-NET-001", "MEDIUM", f"LLM endpoint '{host}' is not an approved destination (data leaves the approved boundary/region)", rp, ln, "P7", "LLM02",
                                           "Use an approved provider/endpoint; confirm data residency and contractual cover."))
    inv = {"frameworks": sorted(ctx["frameworks"]), "models": models, "endpoints": eps, "tools": ctx["inventory"]["tools"], "mcp_servers": ctx["inventory"]["mcp_servers"]}
    uniq, out = set(), []
    for f in ctx["findings"]:
        k = (f["rule"], f["path"], f["line"], f["title"])
        if k not in uniq:
            uniq.add(k)
            out.append(f)
    os.makedirs(a.out, exist_ok=True)
    json.dump({"inventory": inv, "findings": out}, open(os.path.join(a.out, "agent-scan.json"), "w"), indent=1)
    print(f"agent-scan: frameworks={inv['frameworks']} models={len(models)} tools={len(inv['tools'])} mcp={len(inv['mcp_servers'])} findings={len(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
