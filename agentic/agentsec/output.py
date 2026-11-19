"""P3 Output integrity & lineage: check that what an agent *says* can be traced to what it was *given*.

An agent answer is only as trustworthy as its numbers. This module checks that every figure in a model's answer matches a
certified source value (typically the JSON an authoritative tool returned) within a tolerance, and that a structured answer
matches a schema. It returns structured violations (so you can log, retry or refuse) and offers a fail-closed helper.

What it can do:   catch invented / mis-copied / mis-scaled numbers ("revenue grew 14%" when the source says 4.1%).
What it cannot:   judge whether a *claim* is true, catch correct numbers used in a misleading sentence, or verify text that
                  contains no figures. Treat it as one control next to evaluation sets and human review.
Standard library only.
"""
import itertools
import json
import math
import re
from dataclasses import dataclass, field

# ------------------------------------------------------------------------------------------------ figures
_SUFFIX = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mm": 1e6, "mn": 1e6, "million": 1e6, "b": 1e9, "bn": 1e9, "billion": 1e9, "t": 1e12, "trillion": 1e12}
_FIG = re.compile(
    r"(?<![\w.])(?P<cur>[$€£₹])?\s?(?P<sign>[-+−])?(?P<num>\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?|\.\d+)"
    r"(?:\s?(?P<suf>thousand|million|billion|trillion|bn|mm|mn|k|m|b|t)\b)?(?P<pct>\s?%)?", re.I)
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b")
_ORDINAL_OR_LIST = re.compile(r"(?m)^\s*\d{1,2}[.)]\s")          # "1. first point"


@dataclass(frozen=True)
class Figure:
    raw: str                 # text as written, e.g. "$1.2M"
    value: float             # normalised: 1_200_000.0 (percent keeps its number: 45% -> 45.0)
    is_percent: bool
    tolerance: float         # half a unit of the last stated digit (so "1.2M" accepts 1,150,000..1,250,000)
    start: int


@dataclass(frozen=True)
class Violation:
    kind: str                # unsupported_figure | schema | no_sources | error
    message: str
    figure: str = ""
    nearest: str = ""        # closest certified value, to help the reader


@dataclass
class Report:
    ok: bool
    violations: list = field(default_factory=list)
    lineage: dict = field(default_factory=dict)       # figure text -> source path it matched

    def summary(self):
        return "ok" if self.ok else "; ".join(v.message for v in self.violations[:5])


class OutputRejected(ValueError):
    def __init__(self, report):
        super().__init__("answer rejected: " + report.summary())
        self.report = report


def extract_figures(text, *, ignore_years=True, ignore_dates=True, ignore_list_numbers=True):
    """Find numeric figures in free text. Dates, 4-digit years and '1.' list markers are skipped by default."""
    if not isinstance(text, str):
        return []
    scrub = text
    if ignore_dates:
        scrub = _DATE.sub(lambda m: " " * len(m.group(0)), scrub)
    if ignore_list_numbers:
        scrub = _ORDINAL_OR_LIST.sub(lambda m: " " * len(m.group(0)), scrub)
    out = []
    for m in _FIG.finditer(scrub):
        num = m.group("num")
        digits = num.replace(",", "")
        suf = (m.group("suf") or "").lower()
        has_cur, pct = bool(m.group("cur")), bool(m.group("pct"))
        if ignore_years and re.fullmatch(r"(19|20)\d\d", digits) and not (suf or pct or has_cur):
            continue
        scale = _SUFFIX.get(suf, 1.0)
        v = float(digits) * scale
        if m.group("sign") in ("-", "−"):
            v = -v
        decimals = len(digits.split(".")[1]) if "." in digits else 0
        tol = 0.5 * (10 ** -decimals) * scale
        out.append(Figure(m.group(0).strip(), v, pct, tol, m.start()))
    return out


# ------------------------------------------------------------------------------------------------ sources
def flatten_sources(sources, _path="", _depth=0):
    """Turn certified source data into {path: number}. Accepts numbers, dicts, lists, JSON strings (nested to any shape)."""
    out = {}
    if _depth > 12:
        return out
    if isinstance(sources, bool):
        return out
    if isinstance(sources, (int, float)):
        if math.isfinite(sources):
            out[_path or "value"] = float(sources)
    elif isinstance(sources, str):
        s = sources.strip()
        if s[:1] in "{[":
            try:
                return flatten_sources(json.loads(s), _path, _depth + 1)
            except ValueError:
                pass
        for i, f in enumerate(extract_figures(sources, ignore_years=False)):   # numbers quoted inside a source string
            out[f"{_path or 'text'}#{i}"] = f.value
    elif isinstance(sources, dict):
        for k, v in sources.items():
            out.update(flatten_sources(v, f"{_path}.{k}" if _path else str(k), _depth + 1))
    elif isinstance(sources, (list, tuple)):
        for i, v in enumerate(sources):
            out.update(flatten_sources(v, f"{_path}[{i}]", _depth + 1))
    return out


def _close(a, b, tol_abs, rel_tol, abs_tol):
    return abs(a - b) <= max(tol_abs, rel_tol * abs(b), abs_tol)


def _candidates(fig):
    """Values a figure may legitimately correspond to (45% may be stored as 45 or as 0.45)."""
    return [(fig.value, fig.tolerance), (fig.value / 100.0, fig.tolerance / 100.0)] if fig.is_percent else [(fig.value, fig.tolerance)]


def validate_figures(answer, sources, *, rel_tol=0.005, abs_tol=0.0, allow_derived=False, ignore_years=True, min_abs=None):
    """Check every figure in `answer` against the certified `sources`.

    rel_tol       relative tolerance (0.5% by default) on top of the rounding implied by how the figure was written
    allow_derived also accept the sum, difference, product-with-percentage or ratio of two source values (off by default: stricter)
    min_abs       ignore figures whose absolute value is below this (e.g. 1 to skip "2 regions")
    Returns a Report. With no certified sources at all, any figure is unsupported (fail-closed).
    """
    figs = extract_figures(answer, ignore_years=ignore_years)
    if min_abs is not None:
        figs = [f for f in figs if abs(f.value) >= min_abs]
    flat = flatten_sources(sources)
    rep = Report(True)
    if not figs:
        return rep
    if not flat:
        rep.ok = False
        rep.violations.append(Violation("no_sources", f"the answer contains {len(figs)} figure(s) but no certified source values were provided", figs[0].raw))
        return rep
    pool = list(flat.items())
    derived = {}
    if allow_derived and len(pool) <= 200:
        for (pa, a), (pb, b) in itertools.combinations(pool, 2):
            derived[f"({pa})+({pb})"] = a + b
            derived[f"({pa})-({pb})"] = a - b
            derived[f"({pb})-({pa})"] = b - a
            if b:
                derived[f"({pa})/({pb})*100"] = a / b * 100.0
            if a:
                derived[f"({pb})/({pa})*100"] = b / a * 100.0
    for f in figs:
        hit = None
        for val, tol in _candidates(f):
            hit = next((p for p, s in pool if _close(val, s, tol, rel_tol, abs_tol)), None)
            if hit:
                break
            if allow_derived:
                hit = next((p for p, s in derived.items() if _close(val, s, tol, rel_tol, abs_tol)), None)
                if hit:
                    break
        if hit:
            rep.lineage[f.raw] = hit
            continue
        nearest = min(pool, key=lambda kv: min(abs(c - kv[1]) for c, _ in _candidates(f)))
        rep.ok = False
        rep.violations.append(Violation("unsupported_figure", f"figure {f.raw!r} does not match any certified source value", f.raw, f"{nearest[0]}={nearest[1]:g}"))
    return rep


# ------------------------------------------------------------------------------------------------ schema (JSON-Schema subset)
_TYPES = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "array": (list, tuple), "object": dict, "null": type(None)}


def validate_schema(obj, schema, _path="$"):
    """Small JSON-Schema subset: type, enum, required, properties, additionalProperties, items, minimum, maximum, minLength, maxLength, pattern, minItems, maxItems.
    Returns a list of Violation (empty = valid). Unknown types in the schema are violations (fail-closed)."""
    v = []
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        ok = False
        for name in ts:
            py = _TYPES.get(name)
            if py is None:
                return [Violation("schema", f"{_path}: unknown schema type {name!r}")]
            if isinstance(obj, bool) and name in ("number", "integer"):
                continue
            if isinstance(obj, py) and not (name == "integer" and isinstance(obj, float)):
                ok = True
        if not ok:
            return [Violation("schema", f"{_path}: expected {'/'.join(ts)}, got {type(obj).__name__}")]
    if "enum" in schema and obj not in schema["enum"]:
        v.append(Violation("schema", f"{_path}: {obj!r} is not one of {schema['enum']}"))
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if "minimum" in schema and obj < schema["minimum"]:
            v.append(Violation("schema", f"{_path}: {obj} is below the minimum {schema['minimum']}"))
        if "maximum" in schema and obj > schema["maximum"]:
            v.append(Violation("schema", f"{_path}: {obj} is above the maximum {schema['maximum']}"))
    if isinstance(obj, str):
        if "minLength" in schema and len(obj) < schema["minLength"]:
            v.append(Violation("schema", f"{_path}: shorter than {schema['minLength']}"))
        if "maxLength" in schema and len(obj) > schema["maxLength"]:
            v.append(Violation("schema", f"{_path}: longer than {schema['maxLength']}"))
        if "pattern" in schema and not re.search(schema["pattern"], obj):
            v.append(Violation("schema", f"{_path}: does not match the required pattern"))
    if isinstance(obj, (list, tuple)):
        if "minItems" in schema and len(obj) < schema["minItems"]:
            v.append(Violation("schema", f"{_path}: fewer than {schema['minItems']} items"))
        if "maxItems" in schema and len(obj) > schema["maxItems"]:
            v.append(Violation("schema", f"{_path}: more than {schema['maxItems']} items"))
        if "items" in schema:
            for i, x in enumerate(obj):
                v += validate_schema(x, schema["items"], f"{_path}[{i}]")
    if isinstance(obj, dict):
        for k in schema.get("required", []):
            if k not in obj:
                v.append(Violation("schema", f"{_path}: missing required field {k!r}"))
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in obj:
                v += validate_schema(obj[k], sub, f"{_path}.{k}")
        if schema.get("additionalProperties") is False:
            for k in obj:
                if k not in props:
                    v.append(Violation("schema", f"{_path}: unexpected field {k!r}"))
    return v


# ------------------------------------------------------------------------------------------------ one call, fail-closed
def check_answer(answer, sources, *, schema=None, answer_obj=None, **kw):
    """Figures against sources, plus (optionally) `answer_obj` against `schema`. Any internal error is a rejection."""
    try:
        rep = validate_figures(answer, sources, **kw)
        if schema is not None:
            sv = validate_schema(answer_obj if answer_obj is not None else answer, schema)
            if sv:
                rep.ok = False
                rep.violations += sv
        return rep
    except Exception as e:  # noqa: BLE001 - a checker that crashes must not approve
        return Report(False, [Violation("error", f"output check failed ({type(e).__name__}): rejected")])


def require_valid(answer, sources, **kw):
    """Return the answer if it checks out, else raise OutputRejected (carrying the report). Use in front of the user-facing response."""
    rep = check_answer(answer, sources, **kw)
    if not rep.ok:
        raise OutputRejected(rep)
    return answer
