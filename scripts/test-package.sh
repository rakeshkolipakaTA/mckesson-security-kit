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
V="$T/venv/bin/secscan"; VER="$(head -1 VERSION)"
"$V" --version 2>&1 | head -1 | grep -q "secscan $VER"; check "secscan --version prints the packaged version" 0 $?
[ -f "$T/venv/lib/python3."*/site-packages/mckesson_secscan/kit/scripts/scan.sh ]; check "engine is bundled in the package" 0 $?

r="$T/repo"; cp -a examples/clean-python "$r"; rm -rf "$r/.security"; git -C "$r" init -q
echo "== init (thin mode: nothing of the engine is copied into the repo)"
( cd "$r" && "$V" init >"$T/init.log" 2>&1 ); check "secscan init" 0 $?
[ -d "$r/.security/kit" ]; check "no engine copied into the repo" 1 $?
has "lock pins the version" "^version=$VER" "$r/.security/secscan.lock"
has "lock records mode=thin" "^mode=thin" "$r/.security/secscan.lock"
has "lock records the install source" "^source=$HERE" "$r/.security/secscan.lock"
[ -x "$r/.security/secscan" ]; check "launcher shim written" 0 $?
[ -f "$r/.github/workflows/security-scan.yml" ]; check "GitHub workflow written" 0 $?
grep -q '^SEC_PRESET=starter' "$r/.security/config.env"; check "config.env uses the starter preset" 0 $?
o="$(cd "$r" && PATH="$T/venv/bin:$PATH" .security/secscan config show 2>&1)"; grep -q 'preset=starter' <<< "$o"; check "shim uses the installed secscan (versions match)" 0 $?

echo "== a teammate or CI runner with NOTHING installed"
out="$(cd "$r" && env PATH=/usr/bin:/bin:/usr/local/bin HOME="$T/home" SECSCAN_HOME="$T/cache" bash .security/secscan config show 2>&1)"; rc=$?
check "shim installs the pinned version by itself" 0 $rc
[ -x "$T/cache/$VER/bin/secscan" ]; check "pinned version cached outside the repo" 0 $?
echo "$out" | grep -q 'preset=starter'; check "...and it works" 0 $?
out2="$(cd "$r" && env PATH=/usr/bin:/bin:/usr/local/bin HOME="$T/home" SECSCAN_HOME="$T/cache" bash .security/secscan --version 2>&1)"
echo "$out2" | grep -q "pinned to $VER"; check "--version also shows the repo pin" 0 $?
printf 'version=9.9.9\nsource=bad;touch %s/PWNED\n' "$T" > "$T/lock.bad"; cp "$r/.security/secscan.lock" "$T/lock.good"; cp "$T/lock.bad" "$r/.security/secscan.lock"
( cd "$r" && env PATH=/usr/bin:/bin HOME="$T/home" SECSCAN_HOME="$T/cache2" bash .security/secscan scan >/dev/null 2>&1 ); check "a malformed source in the lock is refused (exit 1)" 1 $?
[ ! -e "$T/PWNED" ]; check "...and nothing was executed" 0 $?
cp "$T/lock.good" "$r/.security/secscan.lock"

echo "== first scan through the installed command"
( cd "$r" && PATH="$T/venv/bin:$PATH" .security/secscan doctor >/dev/null 2>&1 ); check "doctor passes" 0 $?
( cd "$r" && PATH="$T/venv/bin:$PATH" .security/secscan scan >"$T/scan.log" 2>&1 ); check "scan on a clean repo exits 0" 0 $?
[ -f "$r/.security/reports/latest/summary.html" ]; check "report written inside the repo's .security/reports" 0 $?
grep -q '"result": "PASS' "$r/.security/reports/latest/summary.json"; check "clean repo passes" 0 $?

echo "== disable / enable (time-boxed)"
cd "$r"; export PATH="$T/venv/bin:$PATH"
secscan disable >/dev/null 2>&1; check "disable without reason/date is refused" 2 $?
secscan disable --until 2020-01-01 --reason test >/dev/null 2>&1; check "disable with a past date is refused" 2 $?
secscan disable --until "$(date -d '+200 days' +%F)" --reason test >/dev/null 2>&1; check "disable beyond 90 days is refused" 2 $?
secscan disable --until "$(date -d '+10 days' +%F)" --reason "pilot freeze" >/dev/null 2>&1; check "disable --until +10d --reason" 0 $?
n=$(ls .security/reports | wc -l)
secscan scan 2>&1 | grep -q 'SECURITY SCANNING IS DISABLED'; check "scan says it is disabled" 0 $?
[ "$(ls .security/reports | wc -l)" = "$n" ]; check "...and writes no report" 0 $?
secscan gate >/dev/null 2>&1; check "gate exits 0 while disabled (visible banner)" 0 $?
secscan enable >/dev/null 2>&1; grep -q 'SEC_DISABLED_UNTIL' .security/config.env; check "enable removes the setting" 1 $?
printf 'SEC_DISABLED_UNTIL=2020-01-01\n' >> .security/config.env
o="$(secscan config show 2>&1)"; echo "$o" | grep -q 'note: SEC_DISABLED_UNTIL=2020-01-01 has passed'; check "an expired disable switches scanning back on by itself" 0 $?
secscan enable >/dev/null 2>&1

echo "== upgrade keeps my settings"
echo "# my edit" >> .security/config.env; secscan config set SEC_PRESET standard >/dev/null
secscan upgrade >/dev/null 2>&1; check "upgrade runs" 0 $?
grep -q 'my edit' .security/config.env && grep -q '^SEC_PRESET=standard' .security/config.env; check "upgrade keeps config.env edits" 0 $?

echo "== uninstall / reinstall"
secscan uninstall --dry-run >"$T/dry.log" 2>&1; [ -x .security/secscan ]; check "--dry-run removes nothing" 0 $?
grep -q 'workflows/security-scan.yml' "$T/dry.log"; check "--dry-run lists the workflow it would remove" 0 $?
secscan uninstall --yes >/dev/null 2>&1; check "uninstall --yes" 0 $?
[ ! -e .security/secscan ] && [ ! -e .security/secscan.lock ] && [ ! -e .github/workflows/security-scan.yml ]; check "generated files removed" 0 $?
[ -f .security/config.env ] && [ -f .security/exceptions.json ]; check "config + exceptions kept" 0 $?
secscan reinstall >/dev/null 2>&1; check "reinstall" 0 $?
[ -x .security/secscan ] && [ -f .security/secscan.lock ] && grep -q '^SEC_PRESET=standard' .security/config.env; check "reinstall restores files and keeps my config" 0 $?
echo "# my own workflow" > .github/workflows/security-scan.yml
secscan uninstall --yes >/dev/null 2>&1; [ -f .github/workflows/security-scan.yml ]; check "a workflow you changed is never deleted" 0 $?
secscan uninstall --yes --purge >/dev/null 2>&1; [ ! -d .security ]; check "--purge removes .security completely" 0 $?

echo "== vendored mode (offline / air-gapped)"
secscan init --vendor >/dev/null 2>&1; check "init --vendor" 0 $?
[ -d .security/kit/scripts ] && grep -q '^mode=vendored' .security/secscan.lock; check "engine copied into .security/kit" 0 $?
o="$(.security/secscan config show 2>&1)"; grep -q 'preset=' <<< "$o"; check "vendored kit runs without secscan on the PATH" 0 $?
secscan init >/dev/null 2>&1; [ -d .security/kit ]; check "re-running init keeps the repo's mode" 0 $?

echo; echo "package test: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
