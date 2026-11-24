# 2. Code analysis (SAST): does our own code contain insecure patterns?

## What it protects against
Most breaches of web applications start with a coding mistake that a scanner can recognise: building a SQL query from user input (SQL injection), passing input to a shell (command injection), echoing input into a page (cross-site scripting), unsafe deserialisation, weak cryptography, fetching a user-supplied URL from the server (SSRF), reading a user-supplied file path (path traversal). Static analysis reads the code (without running it) and flags those patterns on the pull request, when they are cheapest to fix.

## Checks

| Check | Languages | What it looks for | Severity | Stage |
|---|---|---|---|---|
| **Semgrep, default pack** (`p/default`) | all | Broad security rules maintained by the Semgrep community | ERROR = High, WARNING = Medium, INFO = Low | every PR / push |
| **Semgrep, OWASP Top 10** (`p/owasp-top-ten`) | all | Injection, XSS, broken authentication, security misconfiguration, SSRF and the other OWASP Top 10 classes | same | every PR / push |
| **Semgrep, stack packs** | Python, JavaScript/TypeScript (Node), Java, detected from your files | Language rules (`p/python`, `p/javascript`, `p/typescript`, `p/nodejs`, `p/java`) | same | every PR / push |
| **Semgrep, extra packs** (`SEC_SEMGREP_PACKS`) | all | `security-audit`, CWE Top 25, SQL injection, command injection, insecure transport, JWT, plus framework packs chosen by stack (Python: Flask, Django, FastAPI; Node: XSS, Express, React; any repo with a Dockerfile: Dockerfile). On a real app these added findings the default rules did not report | same | every PR / push |
| **Bandit** | Python | `subprocess` with `shell=True`, SQL built from strings, hard-coded temporary paths, weak hashes (MD5, SHA-1), `pickle`, `yaml.load`, hard-coded passwords | by rule | every PR / push |
| **ESLint security plugins** (+ TypeScript) | JavaScript, TypeScript | `eval`, unsafe regular expressions, unsafe DOM writes (`innerHTML`), object injection, non-literal `require` | by rule | every PR / push |
| **SonarQube Community** (optional) | Python, Java, JS and more | Bugs, code smells, security hot-spots, and a quality gate that also fails the gate | by rule | PR / nightly |
| **CodeQL** (optional, GitHub) | Python, JavaScript, Java, Go and more | Data-flow analysis from user input to a dangerous call; results in GitHub's Security tab | by rule | PR / push / weekly |

## How it protects
* New High findings block the merge (once the `standard` preset is on). Medium and Low are shown but do not block.
* Semgrep cannot be turned off by a team. Bandit and ESLint run when a project has Python or Node code.
* **Noise control, set centrally.** Rules that are wrong for everyone are dropped (`configs/semgrep/exclude-rules.txt`). Heuristic rules that cannot tell safe SQL from unsafe, such as `sqlalchemy-execute-raw-query` (which fired 99 times on one real repo), are capped at Medium: still visible, not blocking on their own.
* Test folders (`tests/`, `test/`) are excluded from Bandit and Semgrep. Override in `.security/bandit.yaml`.
* To use rules from an approved offline mirror instead of the Semgrep registry set `SEC_SEMGREP_RULES`.

Choose the extra packs:
```ini
SEC_SEMGREP_PACKS=auto                 # default: choose by detected stack
SEC_SEMGREP_PACKS=none                 # only the default and OWASP packs
SEC_SEMGREP_PACKS=p/jwt,p/xss          # your own list (names are validated)
```

## When it fires
Each finding shows the rule id, file, line and a fix hint, and appears as a marker on the changed line in the pull request. Typical fixes (before/after code) for SQL injection, command injection, XSS, weak hashes and unsafe YAML/pickle: [../fixing-findings.md](../fixing-findings.md). Genuine false positives get a **time-boxed exception** with reason, approver and expiry ([../exceptions-and-baseline.md](../exceptions-and-baseline.md)), not a silent skip.

## Limits
* Pattern matching sees one function or file at a time. It does not follow data across many files the way a full taint engine does. CodeQL and SonarQube's commercial editions go further; the free SonarQube Community edition has no taint analysis.
* Rules fire on risky **patterns**, so there are false positives (Bandit B608 and B108, ESLint `detect-object-injection` are noisy) and misses (business-logic flaws, missing authorisation checks).
* Code outside the detected languages is not analysed.
* Status: **Verified** for Semgrep, Bandit, ESLint and the extra packs. SonarQube is **verified (partial)**: needs a Sonar server and token; run on Python only. The CodeQL workflow is a **template**: not run here, and it needs a public repository or GitHub Advanced Security.
