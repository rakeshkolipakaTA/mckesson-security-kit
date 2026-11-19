"""P7 Data protection & minimisation: classify text before it is sent to a model, logged or stored.

Four levels, highest match wins:  PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED.
Rules combine the PII/secret detectors in pii.py with keyword/pattern rules for health data (PHI), material non-public information
(MNPI), financial and HR data, and internal-only markers. Rules are pluggable: add your own (Rule) or replace the defaults.
`enforce_max_level` is the gate: refuse to send text above the level a destination is approved for.

Limits: pattern matching, not understanding. It will miss data that matches none of the rules and will over-flag harmless text that
happens to use the trigger words. Tune the rules to your data, and treat the result as a minimisation aid, not a DLP product.
The result never contains the matched text, only rule names and counts, so it is safe to log.
Standard library only.
"""
import re
from dataclasses import dataclass, field

from .pii import redact

LEVELS = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")


class ClassificationError(PermissionError):
    pass


@dataclass(frozen=True)
class Rule:
    name: str
    level: str
    pattern: object          # compiled regex
    note: str = ""


def _rx(p):
    return re.compile(p, re.I)


DEFAULT_RULES = [
    # RESTRICTED: regulated identifiers, credentials, MNPI
    Rule("mnpi", "RESTRICTED", _rx(r"\b(material\s+non-?public|mnpi|insider\s+(information|trading)|unannounced\s+(earnings|merger|acquisition)|pre-?announcement|quiet\s+period)\b"), "material non-public information"),
    Rule("phi-identifier", "RESTRICTED", _rx(r"\b(mrn|medical\s+record\s+(number|no\.?)|patient\s+id|npi\s*[:#]?\s*\d{10})\b"), "health record identifier"),
    Rule("phi-icd10", "RESTRICTED", re.compile(r"\b(?:ICD-?10[: ]+)?[A-TV-Z]\d{2}\.\d{1,4}\b"), "ICD-10 diagnosis code (e.g. E11.9)"),
    Rule("bank-account", "RESTRICTED", _rx(r"\b(iban\s*[:#]?\s*[A-Z]{2}\d{2}[A-Z0-9]{10,30}|routing\s+(number|no\.?)\s*[:#]?\s*\d{9}|account\s+(number|no\.?)\s*[:#]?\s*\d{8,17})\b"), "bank account details"),
    # CONFIDENTIAL: business-sensitive and health context
    Rule("phi-context", "CONFIDENTIAL", _rx(r"\b(diagnos(is|ed)|prescription|prescribed|lab\s+results?|medical\s+(history|record)|hipaa|treatment\s+plan|medication)\b"), "health information context"),
    Rule("financial", "CONFIDENTIAL", _rx(r"\b(revenue|ebitda|gross\s+margin|net\s+income|forecast|budget|pricing\s+strategy|rebate|contract\s+price|cost\s+of\s+goods)\b"), "financial / commercial figures"),
    Rule("hr", "CONFIDENTIAL", _rx(r"\b(salary|compensation|performance\s+review|disciplinary|termination|severance|bonus\s+plan)\b"), "HR information"),
    Rule("legal", "CONFIDENTIAL", _rx(r"\b(attorney[- ]client|privileged\s+and\s+confidential|non-?disclosure|nda\b|settlement\s+agreement)\b"), "legal"),
    Rule("confidential-marker", "CONFIDENTIAL", _rx(r"\b(strictly\s+)?confidential\b"), "marked confidential"),
    # INTERNAL
    Rule("internal-marker", "INTERNAL", _rx(r"\b(internal\s+use\s+only|for\s+internal\s+use|do\s+not\s+distribute|not\s+for\s+external)\b"), "marked internal"),
    Rule("internal-host", "INTERNAL", _rx(r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(internal|corp|intra|lan|local)\b"), "internal hostname"),
    Rule("private-ip", "INTERNAL", re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "private IP address"),
]
# pii.py kinds -> level (secrets and government/payment identifiers are RESTRICTED; contact details CONFIDENTIAL)
PII_LEVEL = {"PRIVATE_KEY": "RESTRICTED", "JWT": "RESTRICTED", "API_KEY": "RESTRICTED", "BEARER": "RESTRICTED", "CARD": "RESTRICTED", "SSN": "RESTRICTED",
             "AADHAAR": "RESTRICTED", "PAN": "RESTRICTED", "EMAIL": "CONFIDENTIAL", "PHONE": "CONFIDENTIAL", "NAME": "CONFIDENTIAL", "ADDRESS": "CONFIDENTIAL"}


@dataclass
class Classification:
    level: str = "PUBLIC"
    matches: dict = field(default_factory=dict)       # rule name -> count (never the text)

    def at_most(self, level):
        return LEVELS.index(self.level) <= LEVELS.index(level)


class Classifier:
    def __init__(self, rules=None, *, use_pii=True):
        self.rules = list(DEFAULT_RULES if rules is None else rules)
        self.use_pii = use_pii
        for r in self.rules:
            if r.level not in LEVELS:
                raise ValueError(f"rule {r.name}: unknown level {r.level}")

    def add_rule(self, name, level, pattern, note=""):
        if level not in LEVELS:
            raise ValueError(f"unknown level {level}")
        self.rules.append(Rule(name, level, re.compile(pattern, re.I) if isinstance(pattern, str) else pattern, note))

    def classify(self, text):
        c = Classification()
        if not isinstance(text, str) or not text:
            return c

        def bump(name, level, n):
            c.matches[name] = c.matches.get(name, 0) + n
            if LEVELS.index(level) > LEVELS.index(c.level):
                c.level = level
        if self.use_pii:
            for kind, n in redact(text)[1].items():
                bump(f"pii:{kind.lower()}", PII_LEVEL.get(kind, "CONFIDENTIAL"), n)
        for r in self.rules:
            n = len(r.pattern.findall(text))
            if n:
                bump(r.name, r.level, n)
        return c

    def classify_obj(self, obj, _depth=0):
        """Highest classification found anywhere in a nested dict/list/str (e.g. a whole prompt payload or tool result)."""
        best = Classification()
        if _depth > 20:
            return best
        parts = obj.values() if isinstance(obj, dict) else obj if isinstance(obj, (list, tuple)) else None
        if parts is None:
            return self.classify(obj) if isinstance(obj, str) else best
        for v in parts:
            c = self.classify_obj(v, _depth + 1)
            for k, n in c.matches.items():
                best.matches[k] = best.matches.get(k, 0) + n
            if LEVELS.index(c.level) > LEVELS.index(best.level):
                best.level = c.level
        return best


_DEFAULT = Classifier()


def classify(text):
    return _DEFAULT.classify(text)


def enforce_max_level(text, max_level, *, classifier=None):
    """Raise ClassificationError when `text` is classified above `max_level` (e.g. "INTERNAL" for an external model endpoint).
    Fail-closed: if classification itself errors, the text is refused."""
    if max_level not in LEVELS:
        raise ValueError(f"unknown level {max_level}")
    try:
        c = (classifier or _DEFAULT).classify_obj(text)
    except Exception as e:  # noqa: BLE001
        raise ClassificationError(f"could not classify ({type(e).__name__}): refused") from e
    if not c.at_most(max_level):
        raise ClassificationError(f"data classified {c.level} exceeds the allowed {max_level} (rules: {', '.join(sorted(c.matches))})")
    return c
