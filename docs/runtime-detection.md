# Runtime detection: Falco rules and shipping logs to a SIEM

Scanners find weaknesses **before** release. Runtime detection tells you when something is being exploited **now** (presentation items: undetected agent compromise, eBPF runtime observability, container breakout, SSRF to the metadata service). Two sources feed it: **Falco** (what the containers do) and the agent's own **audit log** (what the agent decided).

**Status: template, not run in production.** The Falco rules were validated with Falco's own checker (`falco --validate`, version 0.39.2: syntax and field names; a deliberately broken rule is rejected) but never ran against a live agent, because Falco needs a node with its kernel driver. The SIEM wiring below is a recipe: verify each setting against your Falco / Falcosidekick / agent versions.

## 1. Falco rules for agent workloads
`configs/runtime/falco-agent-rules.yaml` raises an alert when, inside a container of an agent namespace:

| Rule | Priority | Why it matters |
|---|---|---|
| Shell started | WARNING | a "run this command" tool or a breakout attempt |
| Package manager run | WARNING | runtime installs = supply-chain compromise; images should be immutable |
| Network tool started (curl, nc, socat, nmap) | WARNING | bypasses the application's egress allow-list |
| Service-account token / mounted secret read by an unexpected process | ERROR | credential harvesting |
| Connection to the cloud metadata service (169.254.169.254) | CRITICAL | the classic SSRF target |
| Write into an executable directory | ERROR | dropped or replaced binary |
| Audit log written by a process that is not the agent runtime | CRITICAL | log tampering |

Edit the lists at the top (namespaces, processes allowed to read secrets or write the audit log), run with the alerts on "notice" for a few weeks, then page on WARNING and above.

Deploy with the Falco Helm chart (check the chart documentation for the value names of your version):
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set-file 'customRules.agent-rules\.yaml=configs/runtime/falco-agent-rules.yaml'
```
Check the rules offline at any time (no kernel needed):
```bash
docker run --rm -v "$PWD/configs/runtime:/r:ro" falcosecurity/falco-no-driver:0.39.2 \
  falco -V /etc/falco/falco_rules.yaml -V /r/falco-agent-rules.yaml
```

## 2. Shipping Falco alerts to a SIEM
Run **Falcosidekick** next to Falco (the chart can enable it); it forwards each alert as JSON to one or more outputs:

| SIEM / tool | Route |
|---|---|
| Microsoft Sentinel | Falcosidekick to Azure Event Hubs (or a webhook into a Logic App / data-collection endpoint), then a Sentinel data connector; build an analytic rule on `priority` |
| Datadog | Falcosidekick Datadog output (needs the Datadog API key as a secret), or the Datadog Agent's Falco integration |
| Anything else | Falcosidekick webhook, Loki, Elasticsearch, Kafka, or Slack / Teams for human-readable alerts |

Keep the output fields (`container`, `image`, `ns`, `pod`, `cmdline`) in the alert: they are what an analyst needs.

## 3. Shipping the agent audit log
`agentsec.AuditLog` writes one JSON line per decision with a hash chain (optionally an HMAC). A file on the same host is evidence, not a vault, so copy it off the host as it is written:
1. Write the log to a volume the log shipper can read (for example `/var/log/agent-audit/agent-audit.jsonl`).
2. Tail it with your normal agent: Azure Monitor Agent / Datadog Agent / Fluent Bit (`tail` input, JSON parser) and send to the SIEM or to write-once storage (S3 Object Lock, Azure immutable blob).
3. **Verify the chain** from a different machine than the one that wrote it, on a schedule, and alert when it fails:
   ```python
   from agentsec import verify_chain
   ok, checked, first_bad = verify_chain("/mnt/audit-copy/agent-audit.jsonl", key=AUDIT_KEY)   # HMAC key from your secret store
   # ok is False when a record was edited, removed or reordered; first_bad is the index of the first bad record
   ```
   A failure means a record was edited, removed or reordered. The Falco rule "Audit log modified by an unexpected process" is the real-time companion.
4. Keep the HMAC key out of the agent host if you can (verify elsewhere), otherwise an attacker who owns the host can recompute the chain.

## What this does not do
No alert routing logic, on-call rota or runbook beyond [the incident-response runbook](process/incident-response-runbook.md), and no detection of attacks that leave no trace in syscalls or the audit log (for example a model that is persuaded to give a wrong but harmless-looking answer).
