# Cluster and cloud posture: what is not a repository scan

The repository scans check files (manifests, Terraform, Dockerfiles). Two things live outside the repository and need credentials to look at: **the running Kubernetes cluster** and **the cloud account**. They are provided here as ready-to-run commands and a CI template. **Status: documented and templated, not run in this repository's tests** (no cluster or cloud account was available); try them in a sandbox account first.

## Live cluster (read-only)
| Check | Command (run with a read-only kubeconfig) | What it tells you |
|---|---|---|
| NSA / MITRE hardening | `kubescape scan framework nsa,mitre --format json --output cluster.json` | Privileged pods, missing network policies, over-broad RBAC in the running cluster |
| CIS Kubernetes benchmark (nodes) | `kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml` then `kubectl logs job/kube-bench` | Node and control-plane configuration against CIS |
| Image and workload vulnerabilities | `trivy k8s --report summary cluster` | CVEs and misconfigurations of what actually runs |
| RBAC review | `kubectl auth can-i --list --as system:serviceaccount:<ns>:<sa>` | What a workload identity may do |

Run them on a schedule from a CI job with a read-only service account, and publish the JSON next to the repository reports.

## Cloud account posture (AWS example)
Prowler checks the account against CIS and cloud best practices (public buckets, open security groups, unencrypted volumes, over-privileged roles, missing MFA, public load balancers or telemetry endpoints).

```bash
docker run --rm -v "$PWD/out:/out" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  toniblyx/prowler:stable aws --severity critical high --output-formats json-ocsf -o /out
```
Use short-lived credentials from an OIDC role with the `SecurityAudit` and `ViewOnlyAccess` managed policies only. The GitHub Actions template `modes/per-project/templates/github-actions-cloud-posture.yml` runs it weekly with OIDC (no stored keys) and uploads the report as an artifact.

## Why this is separate
A repository scan answers "is what we are about to deploy safe?". Posture scans answer "is what is deployed, and the account around it, safe right now?". They need different credentials, run on a schedule rather than on pull requests, and their findings belong to the platform team.
