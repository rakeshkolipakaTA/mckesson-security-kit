# Dependency-Track: keep watching the libraries after release

A Warden scan checks your libraries **when it runs**. If a new CVE is published next month for a library you shipped today, nothing tells you until the next scan. Dependency-Track (an OWASP project, free) stores the **SBOM** (bill of materials) of every application and keeps checking it against vulnerability databases **continuously**, and it can notify you the same day.

## What you get
* **One project per repository, one version per branch.** The project is named after the repository (`owner/repo`), the version is the branch (normally `main`, marked as the *latest* version).
* **The SBOM of every scan on `main`** (CycloneDX, written by Trivy as `sbom.cdx.json`). Each upload replaces that version's component list.
* **Vulnerabilities per component** from the Google OSV database (covers Python, npm, Maven, Go, NuGet, Rust, Ruby and PHP), the GitHub advisory database, and NVD. It re-analyses as new advisories arrive.
* **Alerts** when a new vulnerability affects a project (see the setup below), licence information per component, and "which projects use library X" search.
* On every scan Warden prints the numbers it gets back, for example `components 128, vulnerabilities critical 0 high 3 medium 11 low 2`.

On a real test (an old FastAPI sample with 9 libraries) it found 39 vulnerabilities in 6 of them: 1 critical, 11 high.

## Developer: turn it on for your repo
1. Ask the platform team for the Dependency-Track **API server** address (not the web page address) and make sure the CI secret `DTRACK_API_KEY` exists.
2. In `.security/config.env`:
   ```ini
   SEC_DTRACK_URL=https://dtrack-api.example.com
   # optional:
   # SEC_DTRACK_PROJECT=my-service       # default: owner/repo
   # SEC_DTRACK_BRANCHES=main,release    # default: main,master. * = all (including tags and pull requests)
   ```
3. Pass the secret to the scan step (the generated GitHub workflow already does):
   ```yaml
   env:
     DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
   ```
   Jenkins: a *Secret text* credential bound to `DTRACK_API_KEY`. Azure DevOps: a secret variable mapped to `DTRACK_API_KEY`.
4. Keep SBOM generation on (`SEC_SBOM` is on by default). Run a scan on `main`; the last lines should say `dependency-track: uploaded SBOM ... [200]`.

Check without sending anything: `.security/warden config show`, and `.security/warden publish --dry-run`.

**No SBOM, nothing to upload.** Trivy builds the SBOM from your lockfiles and manifests (`requirements.txt`, `package-lock.json`, `pom.xml`, ...). If a scan produced none, Warden says `skipped (this scan produced no SBOM)`. Commit your lockfile: without one the SBOM can only list what is declared, not what is installed.

**To record each release:** Dependency-Track keeps one SBOM per version. To keep a record of every released version as well as `main`, publish on release tags with `SEC_DTRACK_BRANCHES=*` in the release workflow only.

## Using it
| You want | Do |
|---|---|
| See what is vulnerable in one app | *Projects*, the repo, *Audit Vulnerabilities* |
| Which of our apps use library X? | *Components* search, or *Vulnerabilities* then the CVE, which lists affected projects |
| Be told about new vulnerabilities | *Administration, Notifications, Alerts, Create Alert*: scope *Portfolio*, group *NEW_VULNERABILITY* (and *NEW_VULNERABLE_DEPENDENCY*), publisher Slack, Teams, email or webhook |
| Say a finding does not apply | *Audit Vulnerabilities*, set the analysis to *Not affected* with a justification. It stays suppressed on later uploads |
| Fail on licence rules | *Policies*, add a licence policy (optional; Warden's own licence check already runs in the scan) |

## For the platform team: start it and get the key
```bash
scripts/platform-up.sh --dtrack [--expose]      # web on port 8110, API on 8111
scripts/dtrack-bootstrap.sh                     # changes the default admin password, creates the CI key, turns on vulnerability sources
```
The bootstrap does the one-time setup that makes Dependency-Track useful:
1. replaces the default `admin/admin` with the generated password (`DTRACK_ADMIN_PASSWORD` in `~/.warden-platform/platform.env`);
2. creates the team **warden-ci** with only three permissions (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`). The key **cannot** administer the server (checked: it gets HTTP 403 on user management);
3. enables the **Google OSV** vulnerability source for the common ecosystems and restarts the API server once so the first download starts. Out of the box Dependency-Track only uses NVD, which matches Python, npm and Maven packages poorly, and Sonatype OSS Index, which now needs an account: without OSV you would see almost no results;
4. prints `SEC_DTRACK_URL=...` (use the address CI can reach) and `export DTRACK_API_KEY=...` (store as the CI secret).

Optional: `DTRACK_GITHUB_TOKEN=<a GitHub token with no scopes> scripts/dtrack-bootstrap.sh` also enables the GitHub advisory database.

**First hour:** the vulnerability databases are downloaded in the background (PyPI has about 27,000 advisories, Maven about 7,000). Early uploads show few or no vulnerabilities; they appear as the download completes, and projects are re-analysed when you upload again or on Dependency-Track's schedule. The API server needs about 4 GB of memory (it is limited to 4 GB in the compose file).

**Rotate the key:** run the bootstrap again. It creates a fresh key for the same team (delete the old key in *Administration, Access Management, Teams, warden-ci*). Update the CI secret.

**Web address vs API address.** People open the web page (port 8110). CI talks to the API server (port 8111). `SEC_DTRACK_URL` is the API address. The web page needs to know the API address that people's browsers can reach: `platform-up.sh` sets it from `--host`.

Store the key as a GitHub secret as usual; unlike DefectDojo's token it is limited to uploading SBOMs and reading results, so a leak is a much smaller problem (rotate it all the same).

## How it works (for the curious)
Warden posts `sbom.cdx.json` to `POST /api/v1/bom` with `autoCreate=true` (creates the project and version the first time), then waits briefly for processing and reads the project's metrics for the summary line. Code: `scripts/publish_external.py`.

## Troubleshooting
| Message | Cause and fix |
|---|---|
| `DTRACK_API_KEY is not set` | The secret is not passed to the scan step. |
| `API key rejected` (HTTP 401) | Wrong key. Run the bootstrap again. |
| `the key needs the BOM_UPLOAD and PROJECT_CREATION_UPLOAD permissions` (HTTP 403) | The key belongs to a team without those permissions. Use the key from `dtrack-bootstrap.sh`. |
| `could not reach ...` | Use the **API** port (8111), not the web port; and the runner must be able to reach it (self-hosted runner for a private network). |
| `skipped (this scan produced no SBOM)` | `SEC_SBOM=off`, or no manifests Trivy understands. |
| Vulnerabilities `0` right after install | The vulnerability databases are still downloading (see "First hour"). |

## Limits
* Tested against a real Dependency-Track 4.14.7: project created on first upload, 9 components read, 39 vulnerabilities found once OSV was loaded. Not yet run from a GitHub Actions runner.
* Dependency-Track matches on package identifiers in the SBOM. Libraries that are copied into the repo (vendored) or shipped as binaries are only found if the SBOM lists them.
* A vulnerability means the **version** is affected, not that your code calls the affected function.
* Dependency-Track 5.x exists; this kit pins and tests 4.14.7 only.
