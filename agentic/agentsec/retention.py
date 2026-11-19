"""P7 Retention: delete agent data (audit/conversation JSONL files, sqlite tables) once it is older than its retention period.

Dry-run is the DEFAULT: nothing is deleted until you pass dry_run=False. Every purge returns a report you can log.
  RetentionPolicy({"PUBLIC": 30, "INTERNAL": 90, "CONFIDENTIAL": 365, "RESTRICTED": 30}, min_days={"audit": 365})
  purge_jsonl("audit.jsonl", days=400, ts_field="ts", dry_run=False, kind="audit", policy=...)
Hash-chained audit files (agentsec.AuditLog): purging old records keeps the file verifiable. The hash of the last removed record is saved
in `<file>.anchor` and verify_chain() starts from it. The anchor proves the file was purged by policy, not that the removed part was
untouched, so keep your legal minimum (min_days) and ship records to WORM storage before purging.
Limits: file/table level only (no vector stores, object storage or backups), and deletion is not secure erasure of the disk blocks.
Standard library only.
"""
import datetime as dt
import json
import os
import re
import sqlite3
import tempfile
import time

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class RetentionError(ValueError):
    pass


class RetentionPolicy:
    def __init__(self, days_by_level=None, *, min_days=None):
        self.days_by_level = dict(days_by_level or {})
        self.min_days = dict(min_days or {})       # e.g. {"audit": 365}: a floor the purge refuses to go under

    def days_for(self, level):
        if level not in self.days_by_level:
            raise RetentionError(f"no retention period defined for level {level!r}")
        return self.days_by_level[level]

    def check(self, days, kind=None):
        if days is None or days <= 0:
            raise RetentionError("days must be a positive number")
        floor = self.min_days.get(kind, 0) if kind else 0
        if days < floor:
            raise RetentionError(f"{days} days is below the minimum retention of {floor} days for {kind!r}: refused")


def _to_epoch(v):
    """Accept epoch seconds / milliseconds, or an ISO-8601 string."""
    if isinstance(v, (int, float)):
        return v / 1000.0 if v > 1e11 else float(v)
    if isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        try:
            d = dt.datetime.fromisoformat(s)
        except ValueError:
            return None
        return (d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)).timestamp()
    return None


def purge_jsonl(path, *, days, ts_field="ts", dry_run=True, now=None, kind=None, policy=None):
    """Remove JSON-lines records older than `days`. Lines that are not JSON or have no usable timestamp are KEPT (never delete what you cannot date).
    Returns {"path", "dry_run", "kept", "removed", "undated_kept", "cutoff"}."""
    (policy or RetentionPolicy()).check(days, kind)
    now = time.time() if now is None else now
    cutoff = now - days * 86400
    kept, removed, undated, last_removed_hash = [], 0, 0, None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                ts = _to_epoch(rec.get(ts_field)) if isinstance(rec, dict) else None
            except ValueError:
                rec, ts = None, None
            if ts is None:
                undated += 1
                kept.append(line if line.endswith("\n") else line + "\n")
            elif ts < cutoff and not kept:          # only a leading run can be dropped without breaking a hash chain
                removed += 1
                last_removed_hash = rec.get("hash") if isinstance(rec, dict) else None
            else:
                kept.append(line if line.endswith("\n") else line + "\n")
    rep = {"path": path, "dry_run": dry_run, "kept": len(kept), "removed": removed, "undated_kept": undated, "cutoff": cutoff}
    if dry_run or not removed:
        return rep
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".purge-")
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.writelines(kept)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, os.stat(path).st_mode & 0o777)
    os.replace(tmp, path)
    if last_removed_hash:
        with open(path + ".anchor", "w") as a:
            json.dump({"prev": last_removed_hash, "removed_total": removed, "purged_at": round(now, 3), "cutoff": cutoff}, a)
    return rep


def purge_sqlite(db_path, table, ts_column, *, days, ts_kind="epoch", dry_run=True, now=None, kind=None, policy=None):
    """DELETE rows older than `days` from one table. ts_kind: "epoch" (seconds or ms) or "iso" (ISO-8601 text, compared as UTC).
    Table / column names are validated as plain identifiers; values are bound parameters."""
    (policy or RetentionPolicy()).check(days, kind)
    if not (_IDENT.match(table) and _IDENT.match(ts_column)):
        raise RetentionError("table and column must be plain identifiers")
    if ts_kind not in ("epoch", "iso"):
        raise RetentionError("ts_kind must be 'epoch' or 'iso'")
    now = time.time() if now is None else now
    cutoff = now - days * 86400
    con = sqlite3.connect(db_path)
    try:
        if ts_kind == "epoch":
            where, args = f'"{ts_column}" IS NOT NULL AND (CASE WHEN "{ts_column}" > 100000000000 THEN "{ts_column}"/1000.0 ELSE "{ts_column}" END) < ?', (cutoff,)
        else:
            where, args = f'"{ts_column}" IS NOT NULL AND "{ts_column}" < ?', (dt.datetime.fromtimestamp(cutoff, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),)
        n = con.execute(f'SELECT COUNT(*) FROM "{table}" WHERE {where}', args).fetchone()[0]
        total = con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        if not dry_run and n:
            con.execute(f'DELETE FROM "{table}" WHERE {where}', args)
            con.commit()
        return {"db": db_path, "table": table, "dry_run": dry_run, "removed": n, "kept": total - n, "cutoff": cutoff}
    finally:
        con.close()
