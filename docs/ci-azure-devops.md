# Azure DevOps

Requirements: a Microsoft-hosted `ubuntu-latest` agent works (Docker is preinstalled); self-hosted agents need Docker.

## 1. Add the kit
```bash
scripts/warden init /path/to/repo --ci azure
git add .security && git commit -m "Add security scanning (report-only)" && git push
```
This creates `.security/ci/azure-pipelines-security.yml`.

## 2. Create the pipeline
Pipelines > **New pipeline** > your repo > **Existing Azure Pipelines YAML file** > `/.security/ci/azure-pipelines-security.yml` > Save and run.
The run page shows the summary; the **security-report** artifact holds the HTML report.
(Alternatively merge its `steps:` into your existing `azure-pipelines.yml`.)

## 3. Make it block pull requests
While `SEC_PRESET=starter` it never fails. When you set `SEC_PRESET=standard`: Repos > Branches > `main` > Branch policies > **Build validation** > add this pipeline > *Required*.

## 4. Optional: SonarQube
Pipeline variables: `SONAR_HOST_URL` and a **secret** `SONAR_TOKEN`; set `SEC_SONAR=1` in `config.env`; uncomment the `env:` block in the scan step.
Caution: in Azure, an undefined `$(VAR)` is passed literally as the text `$(VAR)`. Only uncomment the mapping when the variable exists.

## 5. Deployment stages
See [cd-release-gates.md](cd-release-gates.md); the YAML has the image-gate step commented at the bottom.

## Notes
Untested against a real McKesson Azure DevOps organisation yet; the YAML parses and uses only `script`, `PublishPipelineArtifact@1` and a logging command.
