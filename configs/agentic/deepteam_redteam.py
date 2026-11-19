#!/usr/bin/env python3
"""LLM-DRIVEN red teaming of your agent with DeepTeam (https://www.trydeepteam.com), mapped to the frameworks on the Agentic Security slides.

TEMPLATE. Verified against deepteam==1.0.10: imports, framework names, and the HTTP target wiring (`--dry-run` calls your agent once and needs no LLM).
NOT verified here: a full run, because it needs an attacker/judge LLM and none was available. Read the warnings first.

 !! DATA: DeepTeam sends your agent's prompts AND responses to the simulator/evaluation model you configure, and its DEFAULT is OpenAI gpt-4o-mini.
    Use an APPROVED model endpoint (Azure OpenAI / Bedrock / internal gateway): implement ApprovedModel below. Never point this at production data.
 !! TELEMETRY: DeepTeam/DeepEval send usage telemetry (Sentry) unless opted out. This script opts out BEFORE importing them. Keep it that way.
 !! SCOPE: these are real attacks. QA/UAT you own only. It complements, not replaces, the deterministic harness (scripts/redteam.py):
    that one proves concrete exploits with canaries; this one explores creative jailbreaks and is judged by an LLM (less reproducible).

Install (separate venv, NOT in your app's):  pip install deepteam==1.0.10 sentry-sdk      (1.0.10 imports sentry_sdk but does not declare it)
Run:   AGENT_URL=https://qa-agent.example.com REDTEAM_TOKEN=... python deepteam_redteam.py --framework owasp-asi [--dry-run]
"""
import argparse
import json
import os
import sys
import urllib.request

os.environ.setdefault("DEEPTEAM_TELEMETRY_OPT_OUT", "YES")   # must be set before deepteam is imported
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")
os.environ.setdefault("DEEPEVAL_GRPC_LOGGING", "NOT_SET")

from deepteam import red_team                                         # noqa: E402
from deepteam.attacks.single_turn import Base64, Leetspeak, PromptInjection   # noqa: E402
from deepteam.frameworks import MITRE, NIST, OWASPTop10, OWASP_ASI_2026, EUAIAct   # noqa: E402
from deepteam.test_case import RTTurn                                 # noqa: E402
from deepteam.vulnerabilities import (BFLA, BOLA, AgentIdentityAbuse, ExcessiveAgency, ExploitToolAgent, GoalTheft,   # noqa: E402
                                      IndirectInstruction, PIILeakage, PromptLeakage)

AGENT_URL = os.environ.get("AGENT_URL", "http://localhost:8000").rstrip("/")
CHAT_PATH = os.environ.get("AGENT_CHAT_PATH", "/chat")
MESSAGE_FIELD = os.environ.get("AGENT_MESSAGE_FIELD", "message")
RESPONSE_FIELD = os.environ.get("AGENT_RESPONSE_FIELD", "response")
TOKEN = os.environ.get("REDTEAM_TOKEN")
FRAMEWORKS = {"owasp-asi": OWASP_ASI_2026, "owasp-llm": OWASPTop10, "mitre": MITRE, "nist": NIST, "eu-ai-act": EUAIAct}


def target(prompt: str, turns=None) -> RTTurn:
    """The system under test: your HTTP agent. Adapt the request/response mapping to your API."""
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})}
    req = urllib.request.Request(AGENT_URL + CHAT_PATH, data=json.dumps({MESSAGE_FIELD: prompt}).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read(500_000).decode(errors="replace"))
        return RTTurn(role="assistant", content=str(body.get(RESPONSE_FIELD, body)))
    except Exception as e:  # noqa: BLE001 - a failing target is a finding about availability, not a crash of the run
        return RTTurn(role="assistant", content=f"[target error: {type(e).__name__}]")


class ApprovedModel:  # subclass deepeval.models.DeepEvalBaseLLM in real use
    """Placeholder: implement load_model/generate/a_generate/get_model_name against YOUR approved model endpoint, then pass an instance as
    simulator_model / evaluation_model below. Left unimplemented on purpose: the default (OpenAI) must not be used silently."""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--framework", choices=sorted(FRAMEWORKS), default="owasp-asi")
    ap.add_argument("--dry-run", action="store_true", help="build everything and call the agent once; no LLM, no attacks")
    a = ap.parse_args()
    framework = FRAMEWORKS[a.framework]()
    vulnerabilities = [PromptLeakage(), PIILeakage(), ExcessiveAgency(), BOLA(), BFLA(), IndirectInstruction(), ExploitToolAgent(), GoalTheft(), AgentIdentityAbuse()]
    attacks = [PromptInjection(), Base64(), Leetspeak()]
    if a.dry_run:
        probe = target("ping")
        print(f"dry-run ok: framework={a.framework}, {len(vulnerabilities)} vulnerabilities, {len(attacks)} attacks, agent answered: {probe.content[:80]!r}")
        return 0
    approved = ApprovedModel()
    if type(approved).__bases__ == (object,):
        sys.exit("Implement ApprovedModel (DeepEvalBaseLLM subclass) for your approved LLM first; refusing to default to OpenAI.")
    risk = red_team(model_callback=target, framework=framework, simulator_model=approved, evaluation_model=approved)
    print(risk)
    return 0


if __name__ == "__main__":
    sys.exit(main())
