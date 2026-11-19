# .security/ - what is in here

| Path | Who edits it | What it is |
|---|---|---|
| `config.env` | **you** | The settings. Start with `SEC_PRESET=starter` (report-only), switch to `standard` when ready. See docs/configuration.md. |
| `exceptions.json` | you, with security approval | Time-boxed suppressions of findings you cannot fix now. |
| `baseline.json` | created by `secscan baseline` | Findings that already existed when you onboarded; only NEW High/Critical ones block. |
| `secscan` | nobody | The command: `secscan doctor`, `secscan scan`, `secscan gate`, `secscan open`. |
| `kit/` | nobody (generated) | The pinned scanner kit. Upgrade by re-running `init` from the framework repo. |
| `ci/` | copy once | Ready-made pipeline files for Jenkins / Azure DevOps and extras. |
| `reports/` | nobody (git-ignored) | Scan output. Open `reports/latest/summary.html`. Never commit or share it. |
| `bandit.yaml`, `gitleaks.toml`, `trivy.yaml`, `eslint.config.mjs` | optional | Override a tool's central config (same file name wins). The severity policy cannot be overridden. |

Exception example (all four fields are mandatory, `expires` max 6 months is recommended):
```json
[{"rule": "B310", "path": "src/app/client.py", "reason": "URL scheme validated in validate_url()", "approved_by": "j.doe (security)", "expires": "2027-03-31"}]
```
Full guide: docs/GETTING-STARTED.md in the framework repo.
