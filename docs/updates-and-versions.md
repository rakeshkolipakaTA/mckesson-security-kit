# How new checks reach your repos (updates and versions)

You do not have to touch each repository when Warden gets a new check, a new rule pack or a fix.

## The default: repos follow the newest release automatically
`warden init` writes `.security/warden.lock` with `channel=auto` and a source like `git+https://github.com/rakeshkolipakaTA/mckesson-security-kit.git@v1`.
`v1` is a **moving tag**: every `v1.x` release moves it. On each run the launcher (`.security/warden`) looks up what `v1` points to and, if it is new, installs it once into a cache (`~/.cache/warden`) before scanning. On a CI runner that means **the next run uses the newest release, with no change and no pull request in the repo**.

| What changes | Reaches repos automatically? |
|---|---|
| New scanner, new rule pack, new check, new report feature, bug fix | **Yes**, on the next run |
| Policy defaults and presets (`policy.json`) | **Yes** |
| The workflow file in the repo (permissions, new steps) | No: run `warden upgrade` once and commit |
| Your own `config.env`, `exceptions.json`, baseline | Never touched |

New checks are normally **report-only first**: your preset decides whether a new finding can block (`starter` never blocks).

## Want reviewed, reproducible upgrades instead? Pin
```bash
warden pin           # fixes the repo to the version running now (channel=pinned); commit .security/warden.lock
warden pin --auto    # go back to following the newest release
warden upgrade --pin # refresh generated files and keep an exact version
```
A pinned repo changes only when someone moves the pin in a pull request. Regulated or release-critical repos should pin; fast-moving repos can follow.

## Offline or blocked network
With `channel=auto` the launcher falls back to the newest copy already in the cache and says so. If nothing is cached it stops and tells you to connect once or pin. A vendored install (`warden init --vendor`) never needs the network for the engine.

## Releasing (for the Warden maintainers)
1. Change code, bump `VERSION` (for example `1.1.0`), run the tests (`make test`), commit.
2. `scripts/release.sh 1.1.0` creates tag `v1.1.0` and moves `v1`. Then push as it prints.
3. Fixes to a released version: bump the patch (`1.1.1`); never re-use a tag.
4. **No new version needed for everyday changes:** commit, then `scripts/release.sh --roll` moves only `v1` to the new commit (push with `git push -f origin v1`). Repos on `channel=auto` use it on their next run; the named tags (`v1.0.1`...) stay put, so pinned repos do not change. Cut a numbered release only when you want a named point to pin or roll back to.
A breaking change needs a new major (`v2`); repos on `v1` do not move to it by themselves.

## Security of automatic updates (read this)
Following a moving tag means **whoever can move `v1` can run code in every repo's CI**. Protect it:
- Make `v*` tags protected in the Warden repository (Settings > Rules > Rulesets > tag ruleset: restrict updates and deletions to the release team), and require reviews on `main`.
- Keep two-person control over releases, and prefer an internal mirror of the repository for production use.
- Repos that cannot accept that risk use `warden pin`, or pin the source to a commit SHA.
The scanners themselves are pinned by digest inside each release (`versions.env`), so a release changes them only deliberately.
