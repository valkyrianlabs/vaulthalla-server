"""Encryption-claims lint: product text may only make the claims spec 05 §6 allows (#364, WS5-a).

Binding spec: `design/encryption/05-claims-and-custody.md` §1, §3.1, §6 and §8. Every encryption claim names its
deployment model, vault type and recovery tier, and only says what is true today: `encrypt_upstream=true` vaults are
`path_v0` (file contents encrypted before upload, file and folder names visible to the storage provider), no vault is
provider-blind, nothing restores a vault from the bucket alone, sealed vaults don't exist yet, and Vaulthalla Cloud
Assisted and Custodial Recovery (Tiers B and C) are planned and not implemented.

The lint scans `docs/` (pages and `stack.toml`), `README.md` and the console sources (`web/src`). A rule matches a
disallowed phrase; the match is accepted only when its scope carries one of the rule's approved qualifiers (for
example "sealed vault" next to "end-to-end encrypted", or a negation such as "not provider-blind"). The scope is the
paragraph in Markdown and TOML, and the line with its neighbours in source code, so wrapped sentences still count.

Run it directly for a report: `python3 tools/contracts/encryption_claims.py [paths...]`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]

# Product text the lint covers, relative to the repository root.
SCAN_ROOTS = ("docs", "README.md", "web/src")
PROSE_SUFFIXES = {".md", ".toml"}
CODE_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs"}

_I = re.IGNORECASE

# Qualifiers shared by several rules.
SEALED = r"\bsealed[- ]vaults?\b"
NEGATED = r"\b(not|isn't|aren't|wasn't|never|no|nor|neither|without|cannot|can't|doesn't|don't)\b"
PLANNED = r"\b(planned|not (yet )?(implemented|available|offered)|isn't (yet )?(implemented|available|offered)|future)\b"
NAME_CAVEAT = (
    r"\bnames?\b[^.]{0,60}\b(visible|exposed|readable|see|sees)\b"
    r"|\bvisible to (the|your) (bucket|storage|provider)"
    r"|\bopaquely named\b"
)


@dataclass(frozen=True)
class Rule:
    """One disallowed claim (spec 05 §6) and the qualifiers that make a mention acceptable."""

    rule_id: str
    pattern: re.Pattern[str]
    why: str
    # Each entry is a regex; the mention is allowed when any of them matches its scope (the paragraph, or the line and
    # its neighbours in code) ...
    allow_if: tuple[re.Pattern[str], ...] = ()
    # ... or, for these, the sentence that holds the mention (negations and "planned" must qualify the claim itself).
    allow_in_sentence: tuple[re.Pattern[str], ...] = ()
    # When set, the rule only applies where this regex also matches the scope (a term that is fine in general but
    # not as a claim about vault encryption, such as "anonymous").
    context: re.Pattern[str] | None = None


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, _I)


FRAMEWORKS = r"(HIPAA|GDPR|SOC ?[12]|PCI(?:[- ]DSS)?|ISO[- ]?27001|FedRAMP|FIPS(?:[- ]140(?:-[23])?)?|CJIS)"

RULES: tuple[Rule, ...] = (
    Rule(
        "superlative",
        _rx(r"\bmilitary[- ]grade\b|\bunbreakable\b|\bunhackable\b|\bbank[- ](level|grade)\b"),
        'spec 05 §6: never "military-grade", "unbreakable", "unhackable" or "bank-level"',
    ),
    Rule(
        "zero-knowledge",
        _rx(r"\bzero[- ]knowledge\b|\bzero[- ]access\b"),
        '"zero-knowledge" is allowed only for sealed vaults and only with the metadata sentence '
        '("The server still sees file sizes, counts and activity times.")',
        allow_if=(_rx(SEALED + r"[\s\S]*still sees file sizes|still sees file sizes[\s\S]*" + SEALED),),
    ),
    Rule(
        "end-to-end",
        _rx(r"\bend[- ]to[- ]end[- ]encrypt\w*|\bE2EE\b"),
        '"end-to-end encrypted" describes sealed vaults only, never server vaults (spec 05 §6)',
        allow_if=(_rx(SEALED),),
    ),
    Rule(
        "blindness",
        _rx(r"\b(provider|operator)[- ]blind\b"),
        "no vault is provider-blind or operator-blind today (`path_v0` names are visible to the provider; spec 05 §3); "
        "never operator-blind while Valkyrian Labs could recover plaintext",
        allow_if=(_rx(SEALED),),
        allow_in_sentence=(_rx(NEGATED + r"\s+(\w+\s+){0,2}(provider|operator)[- ]blind"),),
    ),
    Rule(
        "provider-sees-nothing",
        _rx(
            r"\b(bucket|provider|storage|operator)\b[^.]{0,40}\b(only (ever )?sees?|sees? only|never sees?|knows nothing)\b"
            r"|\bknows nothing about your\b"
        ),
        "`path_v0` objects keep their names: the provider sees file and folder names (spec 05 §6)",
        allow_if=(_rx(r"\bopaquely named\b"), _rx(SEALED)),
    ),
    Rule(
        "nobody-can-read",
        _rx(
            r"\b(nobody|no one|no-one)( else)? (can|could|will) (ever )?(read|access|see|decrypt)\b"
            r"|\b(we|valkyrian labs|vaulthalla) (can't|cannot|can ?not|are unable to|is unable to|never) "
            r"(access|read|see|decrypt) your\b"
            r"|\bneither we nor\b"
            r"|\bonly you can (decrypt|read|access)\b"
        ),
        "whoever runs the daemon holds live vault keys (spec 05 §1): only sealed vaults may say nobody else can read",
        allow_if=(_rx(SEALED),),
    ),
    Rule(
        "encrypted-storage",
        _rx(r"\bencrypted storage\b"),
        '"encrypted storage" needs the name caveat: "File and folder names are visible to your storage provider." '
        "(spec 05 §6, `path_v0`)",
        # A sentence about losing access to encrypted data ("never leave encrypted storage inaccessible") is no claim.
        allow_if=(
            _rx(NAME_CAVEAT),
            _rx(SEALED),
            _rx(r"\bencrypted storage\b[^.]{0,40}\b(inaccessible|undecryptable|unreadable)\b"),
        ),
    ),
    Rule(
        "sealed-overclaim",
        _rx(r"\banonymous\b|\bmetadata[- ]free\b"),
        'sealed vaults are never "anonymous" or "metadata-free" (spec 05 §6)',
        context=_rx(SEALED + r"|\bend[- ]to[- ]end[- ]encrypt|\bE2EE\b|\bzero[- ]knowledge\b"),
    ),
    Rule(
        "compliance",
        _rx(
            r"\b" + FRAMEWORKS + r"[- ](compliant|certified)\b"
            r"|\b(compliant|certified) (with|for|under) " + FRAMEWORKS + r"\b"
        ),
        'compliance belongs to the customer\'s organization: say "Designed to support the technical safeguards in '
        '<framework>; see <doc>." (spec 05 §6)',
        allow_in_sentence=(_rx(NEGATED + r"[^.]{0,40}" + FRAMEWORKS + r"[- ](compliant|certified)"),),
    ),
    Rule(
        "bucket-only-recovery",
        _rx(
            r"\b(recover\w*|restor\w*|rebuild\w*)\b[^.]{0,60}\b(from|with|using) (the|your|its|a) "
            r"(bucket|encrypted (files|objects))( alone| only)\b"
            r"|\b(recover\w*|restor\w*)\b[^.]{0,40}\bfrom the bucket\b[^.]{0,40}\b(alone|only|by itself)\b"
        ),
        "no claim says or implies a vault is recoverable from the bucket alone until WS3-c ships (spec 05 §1)",
        allow_in_sentence=(_rx(NEGATED + r"|\bisn't possible\b|\bis not possible\b"),),
    ),
    Rule(
        "vl-recovers",
        _rx(
            r"\b(valkyrian labs|we) (can|could|will) (recover|restore|decrypt)\b"
            r"|\bwe (can|could|will) restore your keys\b"
            r"|\brecovery (needs|requires) (valkyrian labs|vaulthalla\.cloud|an account|a subscription)\b"
        ),
        "Tier A recovery never needs Valkyrian Labs; it holds no recovery keys by default (spec 05 §1, §6)",
        allow_in_sentence=(_rx(NEGATED),),
    ),
    Rule(
        "cloud-recovery",
        _rx(
            r"\bvaulthalla cloud\b|\bvaulthalla\.cloud\b|\bcloud[- ]assisted\b|\bcustodial\b|\bcloud recovery\b"
            r"|\bmanaged recovery\b|\bkey escrow\b|\bescrow\w*\b"
        ),
        "Vaulthalla Cloud Assisted and Custodial Recovery (Tiers B and C) are planned and not implemented: never "
        "describe them as available, and never tie an account, payment or managed storage to custody (spec 05 §3.1)",
        allow_in_sentence=(_rx(PLANNED), _rx(NEGATED + r"[^.]{0,40}\bescrow")),
    ),
    Rule(
        "custody-tie",
        _rx(
            r"\b(account|payment|subscription|subscribing|managed storage|managed b2|plan)\b[^.]{0,60}"
            r"\b(enrolls?|enables?|includes?|unlocks?|gives?|provides?)\b[^.]{0,40}\b(custody|custodial|key recovery)\b"
        ),
        "an account, payment or managed storage never enrolls anyone in custody or recovery (spec 05 §3.1)",
        allow_in_sentence=(_rx(NEGATED),),
    ),
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    text: str
    why: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule_id}] {self.text!r}: {self.why}"


@dataclass
class _Unit:
    """A span of text a match is judged in: its first line number, its lines, and the scope for qualifiers."""

    first_line: int
    lines: list[str] = field(default_factory=list)
    scope: str = ""


def _normalize(text: str) -> str:
    # Curly apostrophes and quotes (the console uses ’) and Markdown emphasis don't change a claim.
    return text.replace("’", "'").replace("‘", "'").replace("**", "").replace("__", "")


def _prose_units(lines: list[str]) -> list[_Unit]:
    units: list[_Unit] = []
    current: _Unit | None = None
    for number, raw in enumerate(lines, start=1):
        if raw.strip():
            if current is None:
                current = _Unit(first_line=number)
                units.append(current)
            current.lines.append(_normalize(raw))
        else:
            current = None
    for unit in units:
        unit.scope = " ".join(line.strip() for line in unit.lines)
    return units


def _code_units(lines: list[str]) -> list[_Unit]:
    normalized = [_normalize(line) for line in lines]
    units: list[_Unit] = []
    for index, line in enumerate(normalized):
        if not line.strip():
            continue
        window = normalized[max(index - 1, 0) : index + 2]
        units.append(_Unit(first_line=index + 1, lines=[line], scope=" ".join(part.strip() for part in window)))
    return units


def _line_of(unit: _Unit, offset: int) -> int:
    """The 1-based file line that holds character `offset` of the unit's joined text."""
    position = 0
    for index, line in enumerate(unit.lines):
        position += len(line.strip()) + 1
        if offset < position:
            return unit.first_line + index
    return unit.first_line + len(unit.lines) - 1


_SENTENCE_END = re.compile(r"[.!?](?=\s|$)")


def _sentence(text: str, start: int, end: int) -> str:
    """The sentence of `text` that holds the span [start, end)."""
    begin = 0
    for stop in _SENTENCE_END.finditer(text, 0, start):
        begin = stop.end()
    after = _SENTENCE_END.search(text, end)
    return text[begin : after.end() if after else len(text)]


def check_text(text: str, path: str = "<text>", *, prose: bool = True, rules: tuple[Rule, ...] = RULES) -> list[Finding]:
    """Findings for one document. `prose` judges paragraphs (Markdown, TOML); otherwise lines of source code."""
    lines = text.splitlines()
    findings: list[Finding] = []
    for unit in _prose_units(lines) if prose else _code_units(lines):
        # Prose matches across the whole paragraph; code matches only within its own line (the scope adds context).
        haystack = unit.scope if prose else unit.lines[0].strip()
        for rule in rules:
            if rule.context is not None and not rule.context.search(unit.scope):
                continue
            for match in rule.pattern.finditer(haystack):
                if any(qualifier.search(unit.scope) for qualifier in rule.allow_if):
                    continue
                sentence = _sentence(haystack, match.start(), match.end())
                if any(qualifier.search(sentence) for qualifier in rule.allow_in_sentence):
                    continue
                line = _line_of(unit, match.start()) if prose else unit.first_line
                findings.append(Finding(path, line, rule.rule_id, match.group(0), rule.why))
    return findings


def iter_product_files(root: Path = REPO_ROOT) -> list[Path]:
    files: list[Path] = []
    for entry in SCAN_ROOTS:
        target = root / entry
        if target.is_file():
            files.append(target)
            continue
        if not target.is_dir():
            continue
        for path in sorted(target.rglob("*")):
            if not path.is_file() or "node_modules" in path.parts:
                continue
            if path.suffix in PROSE_SUFFIXES or path.suffix in CODE_SUFFIXES:
                files.append(path)
    return files


def check_paths(paths: list[Path], root: Path = REPO_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        try:
            label = str(path.relative_to(root))
        except ValueError:
            label = str(path)
        text = path.read_text(encoding="utf-8")
        findings.extend(check_text(text, label, prose=path.suffix not in CODE_SUFFIXES))
    return findings


def check_repo(root: Path = REPO_ROOT) -> list[Finding]:
    return check_paths(iter_product_files(root), root)


def main(argv: list[str]) -> int:
    paths = [Path(arg).resolve() for arg in argv] if argv else iter_product_files()
    findings = check_paths(paths)
    for finding in findings:
        print(finding)
    if findings:
        print(f"{len(findings)} disallowed encryption claim(s); see design/encryption/05-claims-and-custody.md §6")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
