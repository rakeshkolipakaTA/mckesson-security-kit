# 3. Dependencies (SCA): do the libraries we ship have known vulnerabilities?

## What it protects against
Most of an application is other people's code. When a library gets a public vulnerability (a CVE), every app that uses it is exposed, whether or not the team wrote a line wrong. This is how Log4Shell and the Equifax breach happened. Software composition analysis (SCA) compares every library version you use, **including libraries your libraries pull in**, with databases of known vulnerabilities, and checks that you are allowed to use their licences.

## Checks

| Check | Ecosystems | What it looks for | Severity | Stage |
|---|---|---|---|---|
| **pip-audit** | Python (`requirements*.txt`, `pyproject.toml`, `setup.py`) | Known CVEs in direct and transitive packages, run once per requirements file found in the repo | pip-audit gives none, so High unless Trivy rates the same CVE | every PR / push |
| **npm audit** | Node (one run per `package-lock.json`) | Known CVEs in the lockfile's resolved versions | npm's rating | every PR / push |
| **Trivy file-system scan** | All, including Java (Maven, Gradle) and Go | CVEs across ecosystems from lockfiles and manifests | Trivy's rating | every PR / push |
| **OWASP Dependency-Check** (optional) | Mainly Java | CVEs from the National Vulnerability Database | by CVSS | release |
| **SBOM** (CycloneDX, through Trivy) | All | Not a vulnerability check: a **bill of materials** of everything that ships, written next to the report, so that when a new CVE is announced you know in minutes which apps use the library | n/a | every scan |
| **Dependency-Track** (optional) | All | Not a scan: it keeps the SBOM of each released app and **continuously** re-checks it against OSV, GitHub advisories and NVD, alerting when a NEW CVE hits a library you already shipped. See [../integrations/dependency-track.md](../integrations/dependency-track.md) | by CVE rating | every scan on `main` |
| **Licence compliance** (Trivy) | Lockfiles and images | Licences that may not be used in your product or that need legal review | Deny list = High, review list = Medium, unknown = Low | PR / release |

Default licence lists (legal decides the real ones in `policy.json`): **deny** AGPL, SSPL, BUSL, CC-BY-NC, Commons Clause. **Review** GPL, LGPL, EPL, MPL, CDDL, EUPL, OSL. Permissive licences (MIT, Apache, BSD) are not reported.

## How it protects
* **De-duplication.** pip-audit, npm audit and Trivy can report the same CVE under different ids. Warden merges findings with the same package and id (or any shared alias) in the same manifest into one finding, and the highest known severity wins. A CVE in two different manifests stays two findings, because you must fix both.
* **Honest coverage.** If pins conflict and `pip-audit` cannot resolve the tree, Warden retries on the pinned lines only and lists the file under *Reduced coverage*. If nothing can be audited, that is a tool error, never "no vulnerabilities". For Node without a lockfile, it audits freshly resolved versions and says so.
* New Critical/High CVEs block the pull request gate. On the release gate, **all** Critical and High CVEs block unless they have an approved, unexpired exception.
* Dependency CVEs are **never** excluded by `SEC_EXCLUDE_PATHS`, because hiding them would hide real risk.
* Warden only reports. It never changes the repository (no automatic `npm audit fix`).
* **Keeps libraries fresh:** `warden init` also writes a Dependabot or Renovate configuration so updates arrive as pull requests ([06-supply-chain-and-cicd.md](06-supply-chain-and-cicd.md)).

## When it fires
The **Fix** column names the version to move to. Upgrade the parent package when the vulnerable one is pulled in indirectly (`npm ls <pkg>`, `pip show <pkg>`); one upgrade often clears many rows. If no fix exists yet, add a time-boxed exception that describes the mitigation. Cookbook: [../fixing-findings.md](../fixing-findings.md).

## Limits
* Only **known** vulnerabilities. A brand-new or never-reported flaw is invisible.
* A CVE says the version is vulnerable, not that your code reaches the vulnerable function (no reachability analysis), so some findings do not apply.
* Licence results need licence data in the manifest or installed package. For full coverage, also scan the built image.
* Dependency-Check is wired but needs an NVD API key (or a prepared database) and has not been validated end to end.
* Status: **Verified** for pip-audit, npm audit, Trivy and SBOM. Licences are **verified (partial)**. Dependency-Check is **wired, not run**.
