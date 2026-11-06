"""Scanning entry point: configuration, scoring and verdicts."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from .errors import GuardError
from .normalize import NormalizedText, normalize
from .rules import DEFAULT_RULES, HIDDEN_CHARS_RULE_ID, Rule, Source, is_number

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

Verdict = Literal["allow", "review", "block"]

_MAX_FINDINGS = 100
_EXCERPT_CHARS = 80
_EPSILON = 1e-12
_SOURCES = ("input", "retrieved")


class ClassifierPort(Protocol):
    """Port for an optional caller-supplied classifier."""

    def score(self, text: str) -> float:
        """Return a risk score in [0, 1] for ``text``."""


@dataclass(frozen=True)
class Finding:
    """One rule match. Offsets refer to the original text; ``excerpt`` has at most 80 chars."""

    rule_id: str
    start: int
    end: int
    excerpt: str


@dataclass(frozen=True)
class ScanResult:
    """Outcome of a scan: score in [0, 1], verdict and at most 100 findings ordered by offset."""

    score: float
    verdict: Verdict
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class GuardConfig:
    """Scan configuration, validated on construction.

    Raises:
        GuardError: with code ``invalid_config`` when a value is out of range.
    """

    review_threshold: float = 0.4
    block_threshold: float = 0.7
    classifier_weight: float = 0.5
    max_chars: int = 200_000
    rules: tuple[Rule, ...] = DEFAULT_RULES

    def __post_init__(self) -> None:
        _validate_config(self)


def _validate_config(config: GuardConfig) -> None:
    for name, value in (
        ("review_threshold", config.review_threshold),
        ("block_threshold", config.block_threshold),
        ("classifier_weight", config.classifier_weight),
    ):
        if not is_number(value) or not 0.0 <= value <= 1.0:
            raise GuardError("invalid_config", f"{name} must be a number in [0, 1]")
    if config.review_threshold > config.block_threshold:
        raise GuardError("invalid_config", "review_threshold must not exceed block_threshold")
    max_chars = config.max_chars
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 1:
        raise GuardError("invalid_config", "max_chars must be a positive integer")
    rules = config.rules
    if not isinstance(rules, tuple) or not all(isinstance(r, Rule) for r in rules):
        raise GuardError("invalid_config", "rules must be a tuple of Rule")
    if len({r.id for r in rules}) != len(rules):
        raise GuardError("invalid_config", "rule ids must be unique")


DEFAULT_CONFIG = GuardConfig()


def _match_rule(rule: Rule, text: str, view: NormalizedText) -> list[Finding]:
    on_original = rule.id == HIDDEN_CHARS_RULE_ID
    haystack = text if on_original else view.text
    found: list[Finding] = []
    for match in rule.pattern.finditer(haystack):
        begin, stop = match.span()
        if stop <= begin:
            continue
        if not on_original:
            begin, stop = view.starts[begin], view.ends[stop - 1]
        excerpt = text[begin:stop][:_EXCERPT_CHARS]
        found.append(Finding(rule.id, begin, stop, excerpt))
        if len(found) >= _MAX_FINDINGS:
            break
    return found


def _finding_key(finding: Finding) -> tuple[int, int, str]:
    return (finding.start, finding.end, finding.rule_id)


def _rule_score(weights: Iterable[float]) -> float:
    remaining = 1.0
    for weight in weights:
        remaining *= 1.0 - weight
    return 1.0 - remaining


def _apply_classifier(rule_score: float, value: float, weight: float) -> float:
    if not is_number(value) or not 0 <= value <= 1:
        raise GuardError("classifier_contract", "classifier score must be a number in [0, 1]")
    combined = 1.0 - (1.0 - rule_score) * (1.0 - weight * value)
    return max(rule_score, min(1.0, combined))


def _verdict(score: float, config: GuardConfig) -> Verdict:
    if score >= config.block_threshold - _EPSILON:
        return "block"
    if score >= config.review_threshold - _EPSILON:
        return "review"
    return "allow"


def scan(
    text: str,
    *,
    source: Source = "input",
    config: GuardConfig = DEFAULT_CONFIG,
    classifier: ClassifierPort | None = None,
    on_event: Callable[[Mapping[str, object]], None] | None = None,
) -> ScanResult:
    """Screen ``text`` for prompt injection.

    Args:
        text: Untrusted text, at most ``config.max_chars`` characters.
        source: ``"input"`` for user input or ``"retrieved"`` for retrieved content.
        config: Thresholds, limits and rules.
        classifier: Optional classifier; it can raise the score but never lower it.
        on_event: Optional callback receiving ``verdict``, ``score``, ``rule_ids``, ``source``
            and ``length``. The payload never contains any part of the text. Exceptions raised
            by the callback propagate.

    Returns:
        The score, the verdict and the findings (at most 100, ordered by offset).

    Raises:
        GuardError: ``input_too_large`` (fails closed), ``invalid_config`` or
            ``classifier_contract``. Exceptions raised by the classifier propagate unchanged.
    """
    if not isinstance(text, str):
        raise GuardError("invalid_config", "text must be a str")
    if source not in _SOURCES:
        raise GuardError("invalid_config", "source must be 'input' or 'retrieved'")
    if not isinstance(config, GuardConfig):
        raise GuardError("invalid_config", "config must be a GuardConfig")
    _validate_config(config)
    view = normalize(text, max_chars=config.max_chars)
    fired: dict[str, float] = {}
    findings: list[Finding] = []
    for rule in config.rules:
        if source not in rule.applies_to:
            continue
        found = _match_rule(rule, text, view)
        if found:
            fired[rule.id] = rule.weight
            findings.extend(found)
    findings.sort(key=_finding_key)
    score = _rule_score(fired.values())
    if classifier is not None:
        score = _apply_classifier(score, classifier.score(text), config.classifier_weight)
    verdict = _verdict(score, config)
    logger.debug(
        "scan finished: verdict=%s score=%.3f rules=%d length=%d",
        verdict,
        score,
        len(fired),
        len(text),
    )
    if on_event is not None:
        on_event(
            {
                "verdict": verdict,
                "score": score,
                "rule_ids": tuple(sorted(fired)),
                "source": source,
                "length": len(text),
            }
        )
    return ScanResult(score, verdict, tuple(findings[:_MAX_FINDINGS]))
