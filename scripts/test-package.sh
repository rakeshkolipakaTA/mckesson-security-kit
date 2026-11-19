#!/usr/bin/env bash
# Package test: build + pip-install the kit into a CLEAN virtualenv and exercise what a team lead and a teammate do.
#   install -> init (thin) -> shim -> first scan -> disable/enable -> upgrade -> uninstall/reinstall -> vendored mode.
# Needs network (pip builds the package) and Docker (one real scan). ~3 min.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$HERE"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAILN=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1 (expected $2, got $3)"; FAILN=$((FAILN+1)); fi; }
has() { if grep -qE -- "$2" "$3" 2>/dev/null; then check "$1" 1 1; else check "$1" 1 0; fi; }
no() { if grep -qE -- "$2" "$3" 2>/dev/null; then check "$1" 0 1; else check "$1" 0 0; fi; }

echo "== install into a clean virtualenv"
python3 -m venv "$T/venv" && "$T/venv/bin/pip" install -q "$HERE" >"$T/pip.log" 2>&1; check "pip install of the package" 0 $?
V="$T/venv/bin/warden"; VER="$(head -1 VERSION)"
"$V" --version 2>&1 | head -1 | grep -q "warden $VER"; check "warden --version prints the packaged version" 0 $?
[ -f "$T/venv/lib/python3."*/site-packages/warden_kit/kit/scripts/scan.sh ]; check "engine is bundled in the package" 0 $?

r="$T/repo"; cp -a examples/clean-python "$r"; rm -rf "$r/.security"; git -C "$r" init -q
echo "== init (thin mode: nothing of the engine is copied into the repo)"
( cd "$r" && "$V" init >"$T/init.log" 2>&1 ); check "warden init" 0 $?
[ -d "$r/.security/kit" ]; check "no engine copied into the repo" 1 $?
has "lock pins the version" "^version=$VER" "$r/.security/warden.lock"
has "lock records mode=thin" "^mode=thin" "$r/.security/warden.lock"
has "lock records the install source" "^source=$HERE" "$r/.security/warden.lock"
[ -x "$r/.security/warden" ]; check "launcher shim written" 0 $?
[ -f "$r/.github/workflows/security-scan.yml" ]; check "GitHub workflow written" 0 $?
grep -q '^SEC_PRESET=starter' "$r/.security/config.env"; check "config.env uses the starter preset" 0 $?
o="$(cd "$r" && PATH="$T/venv/bin:$PATH" .security/warden config show 2>&1)"; grep -q 'preset=starter' <<< "$o"; check "shim uses the installed warden (versions match)" 0 $?

echo "== a teammate or CI runner with NOTHING installed"
out="$(cd "$r" && env PATH=/usr/bin:/bin:/usr/local/bin HOME="$T/home" WARDEN_HOME="$T/cache" bash .security/warden config show 2>&1)"; rc=$?
check "shim installs the pinned version by itself" 0 $rc
[ -x "$T/cache/$VER/bin/warden" ]; check "pinned version cached outside the repo" 0 $?
echo "$out" | grep -q 'preset=starter'; check "...and it works" 0 $?
out2="$(cd "$r" && env PATH=/usr/bin:/bin:/usr/local/bin HOME="$T/home" WARDEN_HOME="$T/cache" bash .security/warden --version 2>&1)"
echo "$out2" | grep -q "pinned to $VER"; check "--version also shows the repo pin" 0 $?
printf 'version=9.9.9\nsource=bad;touch %s/PWNED\n' "$T" > "$T/lock.bad"; cp "$r/.security/warden.lock" "$T/lock.good"; cp "$T/lock.bad" "$r/.security/warden.lock"
( cd "$r" && env PATH=/usr/bin:/bin HOME="$T/home" WARDEN_HOME="$T/cache2" bash .security/warden scan >/dev/null 2>&1 ); check "a malformed source in the lock is refused (exit 1)" 1 $?
[ ! -e "$T/PWNED" ]; check "...and nothing was executed" 0 $?
cp "$T/lock.good" "$r/.security/warden.lock"

echo "== first scan through the installed command"
( cd "$r" && PATH="$T/venv/bin:$PATH" .security/warden doctor >/dev/null 2>&1 ); check "doctor passes" 0 $?
( cd "$r" && PATH="$T/venv/bin:$PATH" .security/warden scan >"$T/scan.log" 2>&1 ); check "scan on a clean repo exits 0" 0 $?
[ -f "$r/.security/reports/latest/summary.html" ]; check "report written inside the repo's .security/reports" 0 $?
grep -q '"result": "PASS' "$r/.security/reports/latest/summary.json"; check "clean repo passes" 0 $?
( cd "$r" && PATH="$T/venv/bin:$PATH" GITHUB_STEP_SUMMARY="$T/ghsum.md" GITHUB_REPOSITORY=o/r GITHUB_SHA=abc GITHUB_RUN_ID=1 .security/warden ci-report >"$T/ci.log" 2>&1 ); check "warden ci-report runs (no server, no token)" 0 $?
grep -q "Warden security scan" "$T/ghsum.md"; check "ci-report wrote the GitHub job summary" 0 $?
grep -q "not a pull request" "$T/ci.log"; check "ci-report skips the PR comment outside a pull request" 0 $?
grep -q "warden ci-report" "$r/.github/workflows/security-scan.yml"; check "generated GitHub workflow calls ci-report" 0 $?

echo "== disable / enable (time-boxed)"
cd "$r"; export PATH="$T/venv/bin:$PATH"
warden disable >/dev/null 2>&1; check "disable without reason/date is refused" 2 $?
warden disable --until 2020-01-01 --reason test >/dev/null 2>&1; check "disable with a past date is refused" 2 $?
warden disable --until "$(date -d '+200 days' +%F)" --reason test >/dev/null 2>&1; check "disable beyond 90 days is refused" 2 $?
warden disable --until "$(date -d '+10 days' +%F)" --reason "pilot freeze" >/dev/null 2>&1; check "disable --until +10d --reason" 0 $?
n=$(ls .security/reports | wc -l)
warden scan 2>&1 | grep -q 'SECURITY SCANNING IS DISABLED'; check "scan says it is disabled" 0 $?
[ "$(ls .security/reports | wc -l)" = "$n" ]; check "...and writes no report" 0 $?
warden gate >/dev/null 2>&1; check "gate exits 0 while disabled (visible banner)" 0 $?
warden enable >/dev/null 2>&1; grep -q 'SEC_DISABLED_UNTIL' .security/config.env; check "enable removes the setting" 1 $?
printf 'SEC_DISABLED_UNTIL=2020-01-01\n' >> .security/config.env
o="$(warden config show 2>&1)"; echo "$o" | grep -q 'note: SEC_DISABLED_UNTIL=2020-01-01 has passed'; check "an expired disable switches scanning back on by itself" 0 $?
warden enable >/dev/null 2>&1

echo "== upgrade keeps my settings"
echo "# my edit" >> .security/config.env; warden config set SEC_PRESET standard >/dev/null
warden upgrade >/dev/null 2>&1; check "upgrade runs" 0 $?
grep -q 'my edit' .security/config.env && grep -q '^SEC_PRESET=standard' .security/config.env; check "upgrade keeps config.env edits" 0 $?

echo "== uninstall / reinstall"
warden uninstall --dry-run >"$T/dry.log" 2>&1; [ -x .security/warden ]; check "--dry-run removes nothing" 0 $?
grep -q 'workflows/security-scan.yml' "$T/dry.log"; check "--dry-run lists the workflow it would remove" 0 $?
warden uninstall --yes >/dev/null 2>&1; check "uninstall --yes" 0 $?
[ ! -e .security/warden ] && [ ! -e .security/warden.lock ] && [ ! -e .github/workflows/security-scan.yml ]; check "generated files removed" 0 $?
[ -f .security/config.env ] && [ -f .security/exceptions.json ]; check "config + exceptions kept" 0 $?
warden reinstall >/dev/null 2>&1; check "reinstall" 0 $?
[ -x .security/warden ] && [ -f .security/warden.lock ] && grep -q '^SEC_PRESET=standard' .security/config.env; check "reinstall restores files and keeps my config" 0 $?
echo "# my own workflow" > .github/workflows/security-scan.yml
warden uninstall --yes >/dev/null 2>&1; [ -f .github/workflows/security-scan.yml ]; check "a workflow you changed is never deleted" 0 $?
warden uninstall --yes --purge >/dev/null 2>&1; [ ! -d .security ]; check "--purge removes .security completely" 0 $?

echo "== vendored mode (offline / air-gapped)"
warden init --vendor >/dev/null 2>&1; check "init --vendor" 0 $?
[ -d .security/kit/scripts ] && grep -q '^mode=vendored' .security/warden.lock; check "engine copied into .security/kit" 0 $?
o="$(.security/warden config show 2>&1)"; grep -q 'preset=' <<< "$o"; check "vendored kit runs without warden on the PATH" 0 $?
warden init >/dev/null 2>&1; [ -d .security/kit ]; check "re-running init keeps the repo's mode" 0 $?

echo "== auto-update channel: new releases reach a repo with no change in the repo"
SRCR="$T/srcrepo"; mkdir -p "$SRCR"; ( cd "$HERE" && git ls-files -co --exclude-standard | grep -v '^reports/' | tar -T - -cf - ) | tar -C "$SRCR" -xf -
G="git -C $SRCR -c user.name=t -c user.email=t@t"; $G init -q -b main && $G add -A && $G commit -qm one && $G tag v1.0.0 && $G tag v1
WH="$T/wh"; r2="$T/repo-auto"; cp -a "$HERE/examples/clean-python" "$r2"; rm -rf "$r2/.security"; git -C "$r2" init -q
( cd "$r2" && "$V" init --source "git+file://$SRCR@v1.0.0" >"$T/ia.log" 2>&1 ); check "init from a release tag" 0 $?
has "lock follows the major line (v1), not one release" '^source=git\+file://.*@v1$' "$r2/.security/warden.lock"
has "lock says channel=auto" '^channel=auto$' "$r2/.security/warden.lock"
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden --version >"$T/a1.log" 2>&1 ); check "shim installs the newest v1 on first use" 0 $?
has "first run reports the packaged version" "warden $VER" "$T/a1.log"
[ "$(ls -d "$WH"/auto-* 2>/dev/null | wc -l)" = 1 ]; check "one cached copy" 0 $?
echo "9.9.9" > "$SRCR/VERSION"; $G add -A && $G commit -qm two && $G tag -f v1 >/dev/null
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden --version >"$T/a2.log" 2>&1 ); check "next run after a new release" 0 $?
has "the repo now runs the new release (nothing changed in the repo)" "warden 9.9.9" "$T/a2.log"
[ "$(ls -d "$WH"/auto-* 2>/dev/null | wc -l)" = 2 ]; check "both copies cached" 0 $?
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden --version >"$T/a3.log" 2>&1 ); no "unchanged release is not reinstalled" "installing the newest" "$T/a3.log"
cp "$r2/.security/warden.lock" "$T/lock.bak"; sed -i 's|^source=.*|source=git+file:///nonexistent-warden@v1|' "$r2/.security/warden.lock"
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden --version >"$T/a4.log" 2>&1 ); check "offline: falls back to the newest cached copy" 0 $?
has "offline fallback says so" "cannot reach" "$T/a4.log"
( cd "$r2" && WARDEN_HOME="$T/emptywh" PATH="/usr/bin:/bin" .security/warden --version >"$T/a5.log" 2>&1 ); check "offline with nothing cached fails clearly" 1 $?
has "and tells the user what to do" "warden pin" "$T/a5.log"
cp "$T/lock.bak" "$r2/.security/warden.lock"; $G tag v9.9.9
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden pin >"$T/pin.log" 2>&1 ); check "warden pin" 0 $?
has "pin fixes the exact release" '^source=git\+file://.*@v9\.9\.9$' "$r2/.security/warden.lock"
has "pin sets channel=pinned" '^channel=pinned$' "$r2/.security/warden.lock"
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden --version >"$T/a6.log" 2>&1 ); check "pinned repo runs" 0 $?
has "pinned repo says it is pinned" "pinned to 9.9.9" "$T/a6.log"
( cd "$r2" && WARDEN_HOME="$WH" PATH="/usr/bin:/bin" .security/warden pin --auto >"$T/pa.log" 2>&1 ); check "warden pin --auto" 0 $?
has "back on the major line" '^source=git\+file://.*@v9$' "$r2/.security/warden.lock"
( cd "$r2" && "$V" init --source "git+file://$SRCR@v1.0.0" >"$T/ib.log" 2>&1 ); check "re-running init keeps the channel the team chose" 0 $?
has "channel preserved on upgrade" '^channel=auto$' "$r2/.security/warden.lock"
( cd "$r2" && "$V" init --pin --source "git+file://$SRCR@v1.0.0" >"$T/ic.log" 2>&1 ); check "init --pin" 0 $?
has "--pin writes a pinned lock" '^channel=pinned$' "$r2/.security/warden.lock"
has "--pin keeps the exact tag" '^source=git\+file://.*@v1\.0\.0$' "$r2/.security/warden.lock"

echo "== release script"
RS="$SRCR/scripts/release.sh"
( cd "$SRCR" && "$RS" 9.9.8 >"$T/rl1.log" 2>&1 ); check "release refuses a version that does not match VERSION" 1 $?
echo "9.10.0" > "$SRCR/VERSION"; ( cd "$SRCR" && "$RS" 9.10.0 >"$T/rl2.log" 2>&1 ); check "release refuses a dirty tree" 1 $?
$G add -A && $G commit -qm three
( cd "$SRCR" && "$RS" 9.10.0 >"$T/rl3.log" 2>&1 ); check "release creates the tags" 0 $?
$G rev-parse -q --verify refs/tags/v9.10.0 >/dev/null; check "release tag v9.10.0 exists" 0 $?
[ "$($G rev-parse 'v9^{commit}')" = "$($G rev-parse 'v9.10.0^{commit}')" ]; check "the moving major tag points at the new release" 0 $?
( cd "$SRCR" && "$RS" 9.10.0 >"$T/rl4.log" 2>&1 ); check "release refuses to reuse a tag" 1 $?
has "release prints the push commands and does not push" "git push -f origin v9" "$T/rl3.log"

echo; echo "package test: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
