# Offline and blocked networks

`warden init` already puts the **engine** in the repo (`.security/kit`), so GitHub Actions never pulls anything from our repository. A few things are still downloaded **while a scan runs**. If the client blocks any of these hosts, use the option in the right-hand column. `warden doctor` prints which hosts are reachable from the machine or runner it runs on.

| What is downloaded | Host | If it is blocked | Option |
|---|---|---|---|
| Semgrep rules | semgrep.dev | The Semgrep step produces nothing and **the gate fails closed** (`semgrep=missing`) | Section 1 below |
| Scanner images (Semgrep, Trivy, gitleaks, our two scanner images) | registry-1.docker.io, ghcr.io, mirror.gcr.io | Scans cannot start | Copy them to the client's registry and edit `versions.env` (section 2), or use a self-hosted runner where `warden pull` has run ([platform-setup.md](platform-setup.md)) |
| Vulnerability data | ghcr.io (Trivy), pypi.org (pip-audit), registry.npmjs.org (npm audit) | The library checks fail or are skipped | `TRIVY_DB_REPOSITORY` for a mirror of the Trivy database; allow the two registries |
| GitHub's own actions (`checkout`, `upload-artifact`) | github.com | The workflow cannot start | Normally allowed on GitHub-hosted runners; for self-hosted, mirror them |

## 1. Semgrep when semgrep.dev is blocked
Semgrep's rules come from semgrep.dev. Download them **once**, on any machine that can reach it, and let the scans read the saved copy:
```bash
cd your-repo
.security/warden rules fetch                      # saves the packs this repo uses into .security/semgrep-rules
.security/warden config set SEC_SEMGREP_RULES .security/semgrep-rules
git add .security && git commit -m "Offline Semgrep rules" && git push
```
- It downloads the **same packs** the online scan would use for this repo (OWASP Top 10, CWE Top 25, injection, JWT, the framework packs). Checked on a Python repo: 12 packs, about 2,400 rules, 6 MB. The Warden AI-agent rules ship with the kit and never need the network.
- With `SEC_SEMGREP_RULES` set, **no rule download happens**. In our test the Semgrep container ran with no network at all and still found the planted flaws.
- A relative path is relative to the repo. A missing or empty folder fails the scan clearly; it never reports "clean".
- **Keep the rules fresh.** They change over time: run `warden rules fetch` again now and then (monthly is reasonable) and commit the difference. A scheduled workflow on a runner that can reach semgrep.dev can do it and open a pull request.
- **Licence.** The rules belong to Semgrep and are published under the Semgrep Rules License. Keep them in the client's own repositories or storage for internal use and read the licence before sharing them anywhere else. (`rules fetch` writes a README saying so.) If the client prefers, keep the folder outside the repo (on the runner or an internal artifact store) and set `SEC_SEMGREP_RULES` to its absolute path.
- **No rule files at all?** Another choice is the client's own approved rules: any folder of Semgrep YAML files works.

Not yet tested: a run on a real locked-down network (the block was simulated by giving the Semgrep container no network).

## 2. A client registry for the scanner images
Every image name is one line in `.security/kit/versions.env` (in your repo, because the engine is vendored). Copy the pinned images into the client's registry, then change those lines to the registry paths (`TRIVY_IMAGE`, `GITLEAKS_IMAGE`, `SEMGREP_IMAGE`, `ZIZMOR_IMAGE`, and so on) and review the change in a pull request. Two images, `warden-scanner` and `warden-scanner-node`, are built on first use from `.security/kit/docker/scanner*`; build them once, push them, and point `SCANNER_IMAGE` and `SCANNER_NODE_IMAGE` at the pushed copies (the build itself needs the base image and PyPI). Re-running `warden init` refreshes `versions.env`, so repeat the edit after an upgrade or keep it in a small script. Self-hosted runners can instead run `warden pull` once while they have network access, because Docker keeps the images.

Not tested: pointing the images at a private registry.
