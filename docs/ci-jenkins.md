# Jenkins

Requirements: an agent with **Docker** and `bash`/`python3`; outbound access listed by `secscan doctor`.

## 1. Add the kit
```bash
scripts/secscan init /path/to/repo --ci jenkins     # from the framework folder
git add .security && git commit -m "Add security scanning (report-only)"
```
This creates `.security/ci/Jenkinsfile.security` (stages) and `.security/ci/securityScan.groovy` (shared-library step).

## 2. Add the stage to your Jenkinsfile
Copy stage 1 from `.security/ci/Jenkinsfile.security`:
```groovy
stage('Security scan') {
    steps { sh '.security/secscan scan' }
    post { always { archiveArtifacts artifacts: '.security/reports/20*/summary.html, .security/reports/20*/summary.md', allowEmptyArchive: true } }
}
```
Run the build. Open **Build Artifacts > summary.html**. While `SEC_PRESET=starter` the stage never fails the build. With `SEC_PRESET=standard` it fails the stage (and the build) on violations.

## 3. Optional: SonarQube
Create a Jenkins credential of type *Secret text* with id `sonar-token`, set `SONAR_HOST_URL` as an environment variable on the job/folder, set `SEC_SONAR=1` in `config.env`, and wrap the step with `withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) { ... }` (already in the template).

## 4. Optional: nicer report link
With the HTML Publisher plugin, uncomment the `publishHTML` line to get a *Security report* link on the build page.

## 5. Shared library (platform team, optional)
Put `securityScan.groovy` at `vars/securityScan.groovy` in your shared library. Teams then write `securityScan()` or `securityScan(enforce: true, gate: 'release', image: env.IMAGE)`.

## 6. Deployment stages
See [cd-release-gates.md](cd-release-gates.md): image gate before the push to JFrog/ACR, ZAP after QA deploy.

## Notes
- **Not yet run on a real Jenkins and not syntax-checked**: the stage uses only `sh` and `archiveArtifacts`, so it should work on any declarative pipeline, but treat it as a template to validate once. Tell the platform team if something differs.
- Pull-request builds from untrusted forks run repository code on the agent. That is a Jenkins-wide risk; use your standard controls for untrusted PRs.
