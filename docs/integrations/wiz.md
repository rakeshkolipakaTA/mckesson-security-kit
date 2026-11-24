# Wiz: cloud security platform (GitHub Actions and Azure DevOps, Azure cloud)

**Status: ready to use if you have a Wiz licence, not yet run against a real Wiz tenant.** Everything on Warden's side is tested (with a stand-in `wizcli` and against a real DefectDojo using Wiz's own sample files). What the real `wizcli` accepts depends on the version you install: check the flags with `wizcli --help` before relying on them. Wiz's documentation is behind a customer login ([docs.wiz.io](https://docs.wiz.io/)).

## What Wiz covers, and what Warden covers
Wiz is a commercial platform. It does two different jobs, and they are set up in two different places:

| Job | Where it runs | Who sets it up | In this repository |
|---|---|---|---|
| **A. Scan the code in the pipeline** with the Wiz CLI (`wizcli`): code and libraries (`dir`), Terraform / Kubernetes / ARM / Bicep files (`iac`), a built container image (`docker`) | In your CI (GitHub Actions, Azure DevOps, Jenkins) | The developer or CI owner, in a few minutes | **Yes:** `warden wiz`, plus CI templates. This page, part 1 |
| **B. Scan the running cloud** (Azure subscriptions, virtual machines, AKS clusters, container registries, storage, identities) without installing anything on them, and show **attack paths** | Wiz's own service, connected to your Azure tenant | The cloud / security team, once, in the Wiz portal | **No code needed in Warden.** This page, part 2 describes the Azure setup |

Warden checks what you **build**, before release. Wiz part B checks what you **run**. They answer different questions, so you do not choose one or the other.

---

## Part 1: Wiz CLI scans in your pipeline

### What you need
* A Wiz licence and a **Wiz service account for the CLI** (created by your Wiz administrator in the Wiz portal, under access management / service accounts). It gives you a **client ID** and a **client secret**. Ask the Wiz administrator which permissions the CLI account needs; they are listed in the Wiz portal.
* Two CI secrets with those values: **`WIZ_CLIENT_ID`** and **`WIZ_CLIENT_SECRET`**. One organisation-level secret covers every repository.
* Outbound HTTPS from the runner to Wiz (the CLI download and your Wiz tenant's API and sign-in addresses; the Wiz portal lists them). A self-hosted agent behind a proxy or firewall needs them allowed.

**No licence, no problem:** without both secrets `warden wiz` prints "skipped" and exits successfully, so the same pipeline works before and after you buy.

### Developer: GitHub Actions
1. Make sure the secrets `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` exist.
2. Copy the template: `cp .security/ci/security-wiz.github.yml .github/workflows/wiz.yml` (`warden init` puts it in `.security/ci/`; it is not enabled until you copy it).
3. Commit it. The `Wiz scan` step runs on every pull request and on `main`. On forks (no secrets) and without a licence it is skipped.

### Developer: Azure DevOps
1. Create the pipeline variables `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` (a variable group is best; mark both as secret).
2. *Pipelines, New pipeline, Existing Azure Pipelines YAML file*, pick `.security/ci/azure-pipelines-wiz.yml` (or merge its step into your existing pipeline).
3. Secret variables must be mapped into the step's `env:` as the template does; Azure does not pass them otherwise.

### Developer: Jenkins
Bind two *Secret text* credentials to `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` and run `.security/warden wiz --install` in a stage, as for the other Warden steps.

### On your own machine
```bash
warden creds set WIZ_CLIENT_ID
warden creds set WIZ_CLIENT_SECRET          # typed hidden; stored outside any repository, mode 600
warden wiz --install                         # downloads wizcli (first time), signs in, scans
```

### What `warden wiz` does
1. Reads the two secrets (from the environment, or `..._FILE` paths, or your local credentials file). It **never** reads them from `config.env` (a secret written there is refused with a message) and never prints them (anything the CLI prints is scrubbed).
2. Finds `wizcli` (`SEC_WIZCLI`, then `PATH`, then Warden's cache), or downloads it with `--install`.
3. Signs in with `wizcli auth --id ... --secret ...`.
4. Runs the scans in `SEC_WIZ_SCANS` (default `dir,iac`; add `image` and set `SEC_IMAGE=name:tag` for a built image): `wizcli dir scan --path ./`, `wizcli iac scan --path ./`, `wizcli docker scan --image NAME:TAG`, each with `-o <file>,json` so the result is also saved as JSON in `.security/reports/wiz/`.
5. Reports each scan as **passed**, **policy-failed** (the CLI exited non-zero and wrote a result) or **error** (it could not run), and writes `wiz-summary.json`.
6. If `SEC_DEFECTDOJO_URL` and `DEFECTDOJO_TOKEN` are set, imports the JSON into DefectDojo (see below).

### Settings
| Setting | Meaning | Default |
|---|---|---|
| `SEC_WIZ_SCANS` | `dir`, `iac`, `image` (comma list) | `dir,iac` |
| `SEC_WIZ_ENFORCE=1` (or `--enforce`) | Fail the build when a Wiz **policy** fails, or when a scan could not run | off: report-only, like the `starter` preset |
| `SEC_WIZ_POLICY` | Name of a policy defined in the Wiz portal, passed as `--policy`. Put it in the workflow `env:` if the name has spaces | the tenant's default policies |
| `SEC_IMAGE` | Image for the image scan (Docker must be available) | none |
| `SEC_WIZCLI` | Path to `wizcli` | `PATH`, then the cache |
| `SEC_WIZCLI_URL`, `SEC_WIZCLI_SHA256` | Where `--install` downloads from, and the expected SHA-256 | `https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64`, no hash |

Wiz decides **what** is a violation: the policies, severities and exceptions are defined in the Wiz portal, not in Warden. Warden's own gate (`SEC_PRESET`, baselines, exceptions) does not apply to Wiz results.

**Pin the CLI.** `latest` can change under you, and an unpinned download is a supply-chain risk. Use a version-specific URL from Wiz and its SHA-256: `--install` refuses a file that does not match and prints the hash of what it fetched when none is set. The download must be `https://`.

### Where you see the results
| Place | What shows |
|---|---|
| **The Wiz portal** | The full results, policies, history, and the Wiz view of the finding. This is the main place |
| **The CI log** | What `wizcli` prints (its human-readable summary), plus a one-line result per scan |
| **DefectDojo** (optional) | The three result types are imported with DefectDojo's own Wiz parsers (*Wizcli Dir Scan*, *Wizcli IaC Scan*, *Wizcli Img Scan*), tagged `wiz`, as separate tests next to Warden's findings. Only for `main` and `master` by default (`SEC_DEFECTDOJO_BRANCHES`) |
| Warden's report, the GitHub pull request comment, the SARIF | **Not included.** Wiz results are not merged into Warden's findings or gate. The raw JSON is **not** uploaded as a build artifact either, since it can contain details of findings |

Because Wiz's code scan also looks at libraries and code, **the same issue may appear twice** in DefectDojo: once from Warden's tools (Trivy, Semgrep) and once from Wiz, in different tests. Filter by the `wiz` tag to separate them. They are not merged, as they come from different scanners.

### Troubleshooting
| Message | Cause and fix |
|---|---|
| `wiz: skipped: no Wiz licence credentials` | The secrets are not set or not passed to the step. Expected on forks |
| `wizcli is not installed` | Run `warden wiz --install`, or install it and set `SEC_WIZCLI` |
| `sign-in failed` | The client ID or secret is wrong, the service account was disabled, or the runner cannot reach Wiz. Check the account in the Wiz portal |
| `<kind> scan did not run (exit N)` | The CLI could not run (an unknown flag for your version, a network problem, a missing image). The error text is printed. Run `wizcli <dir\|iac\|docker> scan --help` |
| `a Wiz policy failed. Report-only mode` | The scan worked and a policy failed. Turn on `SEC_WIZ_ENFORCE=1` to block builds |
| `the download does not match SEC_WIZCLI_SHA256` | The file changed or the hash is wrong. Do not install it; get the hash from Wiz |

---

## Part 2: Wiz for your Azure cloud (the cloud team, once)

This part connects Wiz to your Azure tenant so it can scan the running environment. It is done in the Wiz portal and in Azure. It needs **no change in Warden or in any repository.**

### What Wiz can cover in Azure
Once connected, Wiz scans without agents: virtual machines and scale sets, AKS clusters and the images in them, Azure Container Registry, storage accounts, databases, Key Vault configuration, network security groups and public exposure, and Microsoft Entra identities and roles, then joins the findings into attack paths. Which services are covered depends on your Wiz licence.

### Steps
1. **Decide the scope:** a single subscription, a **management group** (covers every subscription under it, now and later), or the whole tenant. A management group is the usual choice, so new subscriptions are covered automatically.
2. **In the Wiz portal, add an Azure connector** (under settings, deployments or connectors; the menu names vary by version). Wiz then gives you the exact setup for your tenant: a script, Azure CLI, Terraform or ARM template that creates an **app registration (service principal)** and assigns it **read-only roles** at the scope you chose. Use what the portal gives you rather than writing your own: it lists the exact roles and API permissions.
3. **Have it reviewed and run by someone who can approve it:**
   * granting roles at subscription or management-group level needs **Owner** or **User Access Administrator** there;
   * the app registration may need **admin consent** in Microsoft Entra for the directory permissions it asks for (read access to identities, used for permission analysis); a Global Administrator or Privileged Role Administrator grants it;
   * your tenant settings may restrict who can create app registrations.
4. **Give Wiz outbound access** if your tenant restricts it, and add the connector. Wiz then starts the first scan and shows the connector's health.
5. **Choose what to scan:** container registries (ACR) and Kubernetes (AKS) are connected separately in the portal when you want image and cluster coverage.
6. **Route the alerts** to the teams: Wiz can notify by email, Slack, Teams, Jira, ServiceNow and webhooks; configure it in the portal.

### Security notes for the Azure connection
* The connector should be **read-only**. Review the roles Wiz asks for and refuse write permissions you did not expect.
* Store the Wiz **service account for the CLI** (part 1) separately from the **cloud connector**. They are different identities with different power.
* Rotate the CLI client secret on a schedule and when someone with access to it leaves. Use a separate service account per environment if your policy requires it.
* Restrict who can read the CI secrets (GitHub Environments with required reviewers, Azure DevOps variable groups with restricted access).

### How part 1 and part 2 work together
* Part 1 stops a bad Terraform file, a vulnerable library or a risky image **before** it ships.
* Part 2 finds the same kind of problem **after** it ships, and the ones created by hand in the Azure portal.
* If your licence includes Wiz's code-to-cloud features and your repositories are connected in the portal, Wiz can link a running workload back to the repository and pipeline that built it, so a cloud finding points to the code to fix. Ask your Wiz contact whether that is in your licence.

## Limits
* **Not tested against a real Wiz tenant.** No Wiz account was available. The Warden side is tested with a stand-in `wizcli` (14 tests: no licence means nothing runs, the commands, secrets never printed, policy failure versus error, enforcement, safe install) and the DefectDojo import was run on a real DefectDojo with Wiz's own sample files for all three scan types (a repeat import changes nothing). The flags `warden wiz` passes follow Wiz's published CLI usage: `auth --id --secret`, `dir|iac scan --path`, `docker scan --image`, `-o <file>,json`, and `--policy` (only if you set `SEC_WIZ_POLICY`). Verify them on your installed version.
* The exit-code rule (non-zero with a result file = a policy failed; non-zero without = an error) is Warden's reading of how the CLI behaves. Confirm it with a deliberately failing policy before you turn on `SEC_WIZ_ENFORCE`.
* The cloud part (part 2) is guidance only: the exact roles and permissions are Wiz's, shown in its portal for your tenant and version.
* The Wiz CLI download is for Linux x64. Other platforms need a different URL from Wiz.
* Wiz results are not part of Warden's gate, report or pull request comment.

Related: Warden's own open-source cloud checks (Prowler template, kubescape and Trivy for clusters, [../cloud-and-cluster.md](../cloud-and-cluster.md)) stay available and cost nothing; they do not do attack paths. DefectDojo's Wiz parsers: [Wizcli Dir](https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/wizcli_dir/), [Wizcli IaC](https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/wizcli_iac/), [Wizcli Img](https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/wizcli_img/).
