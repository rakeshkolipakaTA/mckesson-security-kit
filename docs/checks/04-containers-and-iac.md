# 4. Containers and infrastructure as code: are Dockerfiles, images and cloud config safe?

## What it protects against
Many incidents are not bugs in the application but **settings**: a container that runs as root, a Kubernetes pod with full host privileges, a storage bucket open to the internet, a database with no encryption, a base image with a known critical flaw. These settings are written as files (Dockerfile, Kubernetes YAML, Helm, Terraform, CloudFormation), so they can be checked on the pull request before anything is deployed.

## Checks

| Check | Looks at | What it looks for | Severity | Stage |
|---|---|---|---|---|
| **Trivy Dockerfile checks** | Dockerfiles | Runs as root, `ADD` instead of `COPY`, secrets in `ENV`, missing `HEALTHCHECK`, `latest` tag | by rule | every PR / push |
| **Trivy Kubernetes / Helm checks** | Manifests, Helm charts | Privileged pods, no `securityContext`, writable root filesystem, host networking, risky ClusterRoles. On the pilot repo it found real issues | by rule | every PR / push |
| **Trivy Terraform / CloudFormation checks** | IaC files | Public buckets, SSH open to the world, unencrypted or publicly reachable databases | by rule | every PR / push |
| **kubescape** (NSA hardening framework) | Kubernetes manifests | Privilege, root, writable filesystem, missing resource limits and network policies | **advisory**: one level below Trivy | every PR / push |
| **Trivy image scan** | A built Docker image | OS-package and library CVEs, **and secrets inside the image** | by CVE rating | release (after `docker build`, before push) |
| **Trivy CIS Docker benchmark** | A built Docker image | Image configuration against the CIS Docker benchmark | advisory, Medium at most | release |
| **Live cluster posture** (kubescape, kube-bench, `trivy k8s`) | The running cluster | RBAC, network policy, node configuration | by rule | scheduled; commands in [../cloud-and-cluster.md](../cloud-and-cluster.md) |
| **Cloud account posture** (Prowler) | A cloud account | Public buckets, open security groups, public load balancers, weak IAM | by rule | scheduled; workflow template |

## How it protects
* **The image gate is the most important step.** Run it after the build and before pushing to the registry. With `warden gate --gate release --image app:tag` any Critical or High finding in code, dependencies **or the image** stops the push, unless it has an approved, unexpired exception. See [../cd-release-gates.md](../cd-release-gates.md).
* A bad Dockerfile or manifest is caught while it is still a diff, not after a cluster has accepted it.
* Image secrets are checked as well as image CVEs, because a key removed in a later layer is still in the earlier one.
* Pointing at an image: set `SEC_IMAGE=name:tag` (in CI this is one line in the workflow).
* kubescape and the CIS check are **advisory** on purpose, so frameworks that disagree with Trivy inform the review without double-blocking a merge.

## When it fires
Each finding names the file and the setting to change, for example: run as a non-root `USER`, set `securityContext.runAsNonRoot: true`, `readOnlyRootFilesystem: true` and `allowPrivilegeEscalation: false`, drop capabilities, set resource limits, turn encryption on, close port 22 to `0.0.0.0/0`. For CVEs in a base image, rebuild on a patched base tag (and prefer a slim or distroless base).

## Limits
* Static checks read what is **written**, not what is **deployed**. A cluster edited by hand, or a cloud account changed in the console, is only seen by the scheduled live checks, which are templates or documented commands here.
* kubescape skips Helm templates it cannot render. Trivy's CIS check is not a full CIS audit of the host.
* A scan of the image tells you about packages inside it, not about how it is run (see the Falco rules in [10-workflow-detection-process.md](10-workflow-detection-process.md)).
* Status: **Verified** for the Dockerfile, Kubernetes, Terraform and CloudFormation checks (Terraform proven on `examples/iac-sample`), kubescape, the image scan and the CIS check. Live cluster posture is **documented, not run** (no cluster available). Prowler is a **template** (no cloud account available).
