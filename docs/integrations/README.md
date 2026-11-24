# Integrations: SonarQube, DefectDojo, Dependency-Track and Wiz

Warden scans a repository and always shows the result **inside GitHub** (run summary, markers on the changed lines, one pull request comment). That needs no server. Optional tools can receive the same scan, each for a different job (Wiz is the odd one out: it is a licensed product that runs its own scans, see below):

| Tool | Job | Who looks at it | What Warden sends | Guide |
|---|---|---|---|---|
| **SonarQube** | Code quality and code-security review, with its own quality gate | Developers, and the client who asked for it | The source code (analysed by Sonar's scanner) | [sonarqube.md](sonarqube.md) |
| **DefectDojo** | One register of **all** findings from all Warden tools, across all repos: owners, deadlines, accepted risks, tickets, management reports | Security team, engineering leads | The findings of every scan (Secrets, SAST, SCA, IaC, DAST, agent checks) | [defectdojo.md](defectdojo.md) |
| **Dependency-Track** | Keeps watching the libraries you shipped and alerts when a **new** CVE is published, even if nobody scans that week | Security team | The SBOM (bill of materials) of every scan | [dependency-track.md](dependency-track.md) |
| **Wiz** (needs a licence) | Commercial cloud security platform. Pipeline: the Wiz CLI scans code, IaC files and images. Cloud: Wiz scans your running Azure environment and shows attack paths | Security and cloud teams | Nothing from Warden to Wiz: `warden wiz` runs the Wiz CLI, and its results can be imported into DefectDojo | [wiz.md](wiz.md) |

You choose per repository which of them to use. A repository can use none, one, two or all three. Each is independent of the others, and none of them is needed for the scan itself.

## What a developer does (the same three steps for each tool)

1. **Ask the platform team** for the tool's **address** and its **CI secret** (one organisation-level secret usually covers every repo, so often there is nothing to ask).
2. **Add the address** to `.security/config.env` (not secret, reviewed with the code).
3. **Pass the secret** to the scan in your CI workflow. The workflow that `warden init` generates already has these lines; remove the `#` if your CI needs it, or just make sure the secret exists.

Then run a scan on your main branch. The last lines of the scan say what was sent.

| | Setting in `.security/config.env` (not secret) | CI secret | Switch-on rule |
|---|---|---|---|
| SonarQube | `SEC_SONAR=on`, `SEC_SONAR_KEY=` (optional); the server address is set once in `configs/central.env` as `SEC_SONAR_HOST_URL` | `SONAR_TOKEN` | `SEC_SONAR=on` |
| DefectDojo | `SEC_DEFECTDOJO_URL=https://defectdojo.example.com` | `DEFECTDOJO_TOKEN` | the URL is set |
| Dependency-Track | `SEC_DTRACK_URL=https://dtrack-api.example.com` (the **API server** address) | `DTRACK_API_KEY` | the URL is set |
| Wiz | `SEC_WIZ_SCANS=dir,iac` (optional); copy the Wiz workflow template | `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` | both secrets exist (no licence = the step is skipped) |

Secrets are never written in `config.env`. If you put one there by mistake, Warden refuses it with a message. For your own machine use `warden creds set NAME`.

### Which branches publish
To keep the registers meaningful, DefectDojo and Dependency-Track only receive scans of **`main` and `master`** by default. Pull request scans still show their result in GitHub; they are simply not copied into the registers. Change it per tool:
```ini
SEC_DEFECTDOJO_BRANCHES=main,release    # comma list, or * for every branch
SEC_DTRACK_BRANCHES=main,release
```
`warden publish` (run by hand) always sends the newest local report, whatever the branch.

### Check that it works
```bash
.security/warden config show      # prints each URL and whether its secret is "set"
.security/warden scan             # on CI, or locally with the secrets in your shell
.security/warden publish          # re-send the newest report to every configured tool; it fails loudly if it cannot
```
Typical last lines of a scan on `main`:
```
defectdojo: published acme/shop (main) -> https://defectdojo.example.com [201]  new 0, closed 2, reactivated 0, open now 41
dependency-track: uploaded SBOM for acme/shop version main -> https://dtrack-api.example.com [200]  components 128, vulnerabilities critical 0 high 3 medium 11 low 2
```

### A publishing problem never breaks your build
If a server is down, a secret is missing or a token is wrong, the scan prints one warning line and carries on. The gate (pass or fail) depends only on the scan, never on these tools. `warden publish` (a deliberate send) exits with an error instead, so you can see the cause.

## Which screen answers which question

| Question | Look at |
|---|---|
| What must I fix in **this pull request**? | GitHub: the PR comment, file markers and run summary |
| Is my code clean, any smells or hot-spots in this project? | SonarQube |
| What are **all** our open findings, who owns them, what is overdue, what did we accept? | DefectDojo |
| A new CVE was announced in library X today: which of our apps use it? | Dependency-Track |
| Is something in our running Azure environment exposed, and what could an attacker chain together? | Wiz (needs a licence) |
| Which repos have no scan, or a failing gate, at a glance? | Warden dashboard (optional, lightweight), or DefectDojo |

## What each tool receives, and what is not sent
* **Source code** goes only to SonarQube (its scanner reads the files) and, if you use it, to Wiz (the Wiz CLI scans the checkout and talks to your Wiz tenant). DefectDojo and Dependency-Track never receive your source.
* **DefectDojo** receives, per finding: severity, tool, rule, file path and line, title, fix hint, and Warden's fingerprint. Secrets are already redacted by the scanners. It does **not** receive raw tool output.
* **Dependency-Track** receives the SBOM: package names and versions (and their licences), nothing else.

## For the platform team: start the servers
```bash
scripts/platform-up.sh --defectdojo --dtrack            # + SonarQube and the dashboard, as before
scripts/platform-up.sh --defectdojo --dtrack --expose   # also open DefectDojo and Dependency-Track to other machines (CI runners, people)
```
* DefectDojo listens on port **8100**, Dependency-Track on **8110** (web) and **8111** (API, what CI talks to). Override with `--defectdojo-port`, `--dtrack-port`, `--dtrack-api-port`.
* They listen on **localhost only** until you add `--expose`, so a fresh install is not reachable from the network with default settings. When you expose them, open only those ports, restrict them to company IP ranges, and put TLS in front (all of them speak plain HTTP).
* Strong random passwords and keys are generated once into `~/.warden-platform/platform.env` (mode 600; never printed, never in git). There are no default credentials left in use.
* One-time setup after the first start: `scripts/defectdojo-bootstrap.sh` and `scripts/dtrack-bootstrap.sh` (each prints the CI secret). SonarQube: `scripts/sonar-bootstrap.sh` as before.
* Put the addresses once in `configs/central.env` (`SEC_DEFECTDOJO_URL`, `SEC_DTRACK_URL`) and release a new Warden version, so every repo inherits them. Details of where each value goes (GitHub, Jenkins, Azure DevOps): [../integrations.md](../integrations.md).
* Memory: DefectDojo needs about 2 GB and Dependency-Track's API server is limited to 4 GB. Give the server 8 GB of free memory for both, plus SonarQube.
* Images are pinned in `versions.env` and pulled from Docker Hub (DefectDojo's own registry logs which organisation pulls).

## Limits
* The publishing logic is tested against mock servers and against **real DefectDojo 3.5.300 and Dependency-Track 4.14.7 containers** (see the status lines in each guide). It has **not** yet run from a GitHub Actions runner against a server on a private network: that needs a self-hosted runner or a public, IP-restricted address.
* SonarQube Community has no branch or pull request analysis; that needs a paid edition.
* Single sign-on for DefectDojo and Dependency-Track is possible in the products themselves but is not configured by Warden.
