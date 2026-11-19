"""P5/P7: mask secrets and personal data before they reach logs, traces, prompts archives or third-party models.
Regex based: a good first line of defence, NOT a complete PII detector. Beyond secrets/IDs it masks names introduced by an honorific
("Dr. Jane Smith", "my name is Jane Smith") and simple street addresses ("221 Baker Street, Apt 4B"); free-text names without such a cue
and non-US address styles are NOT caught. For regulated data add Microsoft Presidio (`redact(text, presidio=True)`, needs
`pip install presidio-analyzer` + a spaCy model) or a cloud DLP service."""
import os
import re

_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{30,})\b")),
    ("BEARER", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("CARD", re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AADHAAR", re.compile(r"(?<![\d-])(?<!\d )[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![ -]?\d)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("PHONE", re.compile(r"(?<![\w.-])(?<!\d )\+?\(?\d[\d ()-]{8,17}\d(?![\w.-])(?![ -]\d)")),
    # context-cued names and street addresses (run last so numbers/IDs were already handled)
    ("NAME", re.compile(r"\b(?:(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Madam)\.?\s+|(?i:my\s+name\s+is\s+))[A-Z][a-z]+(?:[ -][A-Z][a-z]+){0,2}\b")),
    ("ADDRESS", re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Highway|Hwy)\b\.?(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl)\.?\s*#?\w+)?")),
]
_SENSITIVE_KEYS = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|session[_-]?id)")


def _luhn(digits):
    s = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        s += n
    return s % 10 == 0


def presidio_available():
    try:
        import presidio_analyzer  # noqa: F401
        return True
    except ImportError:
        return False


def _presidio_mask(text, counts, mask, entities, language):
    from presidio_analyzer import AnalyzerEngine
    global _PRESIDIO
    try:
        eng = _PRESIDIO
    except NameError:
        model = os.environ.get("AGENTSEC_SPACY_MODEL")      # default: Presidio's own (en_core_web_lg); set e.g. en_core_web_sm for a smaller one
        if model:
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            nlp = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": language, "model_name": model}]}).create_engine()
            eng = _PRESIDIO = AnalyzerEngine(nlp_engine=nlp, supported_languages=[language])
        else:
            eng = _PRESIDIO = AnalyzerEngine()
    spans = sorted(eng.analyze(text=text, language=language, entities=entities), key=lambda r: r.start, reverse=True)
    last = len(text) + 1
    for r in spans:                       # right to left, skipping overlaps
        if r.end > last:
            continue
        text = text[:r.start] + mask.format(kind=r.entity_type) + text[r.end:]
        counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
        last = r.start
    return text


def redact(text, *, mask="[{kind}]", presidio=False, presidio_entities=("PERSON", "LOCATION", "NRP", "MEDICAL_LICENSE"), language="en"):
    """Return (redacted_text, {kind: count}). presidio=True first masks names/places with Microsoft Presidio (raises RuntimeError if it is
    not installed: a request for stronger masking must never silently become weaker)."""
    counts = {}
    if not isinstance(text, str) or not text:
        return text, counts
    if presidio:
        if not presidio_available():
            raise RuntimeError("presidio=True needs `pip install presidio-analyzer` and a spaCy model (python -m spacy download en_core_web_lg)")
        text = _presidio_mask(text, counts, mask, list(presidio_entities), language)
    for kind, rx in _PATTERNS:
        def sub(m, kind=kind):
            if kind == "CARD":
                digits = re.sub(r"\D", "", m.group(0))
                if not (13 <= len(digits) <= 19 and _luhn(digits)):
                    return m.group(0)
            if kind == "PHONE":
                digits = re.sub(r"\D", "", m.group(0))
                if not (10 <= len(digits) <= 15) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", m.group(0).strip()):
                    return m.group(0)   # too short/long, or an ISO date
            counts[kind] = counts.get(kind, 0) + 1
            return mask.format(kind=kind)
        text = rx.sub(sub, text)
    return text, counts


def redact_obj(obj, *, _depth=0):
    """Recursively mask a dict/list/str structure (e.g. a log record). Values under sensitive-looking keys are removed entirely."""
    if _depth > 20:
        return "[TRUNCATED]"
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if isinstance(k, str) and _SENSITIVE_KEYS.search(k) else redact_obj(v, _depth=_depth + 1)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _depth=_depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact(obj)[0]
    return obj
