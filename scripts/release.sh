#!/usr/bin/env bash
# Cut a release of Warden. Repos on channel=auto follow the moving major tag (v1) and get the new release on their next CI run.
#   scripts/release.sh 1.1.0        creates tag v1.1.0 and moves tag v1 to it (does NOT push; prints the commands)
#   scripts/release.sh --roll       moves only the major tag (v1) to the current commit: repos on channel=auto get it on their next run, no new version
#                                   number is created and v1.x tags stay untouched (pinned repos do not change)
# Rules: VERSION must equal the number you pass, the tree must be clean, and the test suites must have passed (run `make test`).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [ "${1:-}" = "--roll" ]; then
  [[ "$(head -1 VERSION)" =~ ^([0-9]+)\. ]] || { echo "VERSION is not like 1.2.3" >&2; exit 2; }
  MAJOR="v${BASH_REMATCH[1]}"
  [ -z "$(git status --porcelain)" ] || { echo "the working tree has uncommitted changes: commit them first" >&2; exit 1; }
  git tag -f -a "$MAJOR" -m "Warden $MAJOR rolling at $(git rev-parse --short HEAD)" >/dev/null
  echo "moved $MAJOR to $(git rev-parse --short HEAD) (no new version). Publish with:"
  echo "  git push origin main && git push -f origin $MAJOR"
  echo "Repos on channel=auto use it from their next run. Repos that ran 'warden pin' do not change."
  exit 0
fi
V="${1:?usage: scripts/release.sh X.Y.Z | --roll}"
[[ "$V" =~ ^([0-9]+)\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like 1.2.3" >&2; exit 2; }
MAJOR="v${BASH_REMATCH[1]}"
[ "$(head -1 VERSION)" = "$V" ] || { echo "VERSION says $(head -1 VERSION), not $V: bump it and commit first" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the working tree has uncommitted changes: commit them first" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v$V" >/dev/null && { echo "tag v$V already exists (releases are immutable; bump the version)" >&2; exit 1; }
git tag -a "v$V" -m "Warden $V"
git tag -f -a "$MAJOR" -m "Warden $V (moving tag: newest $MAJOR release)" >/dev/null
echo "created v$V and moved $MAJOR to it. Publish with:"
echo "  git push origin main && git push origin v$V && git push -f origin $MAJOR"
echo "Every repo on channel=auto uses this release from its next run. Repos that ran 'warden pin' stay on their version until they choose to move."
