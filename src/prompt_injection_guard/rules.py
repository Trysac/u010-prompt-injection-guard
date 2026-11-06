"""Rule model and the default rule set."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

from .errors import GuardError

Source = Literal["input", "retrieved"]

HIDDEN_CHARS_RULE_ID = "unicode.hidden_chars"

_SOURCES: frozenset[str] = frozenset(("input", "retrieved"))
_BOTH: frozenset[Source] = frozenset(("input", "retrieved"))
_RETRIEVED_ONLY: frozenset[Source] = frozenset(("retrieved",))


def is_number(value: object) -> bool:
    """Return True for finite ints and floats; booleans are rejected."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _valid_sources(value: object) -> bool:
    return isinstance(value, frozenset) and bool(value) and value <= _SOURCES


@dataclass(frozen=True)
class Rule:
    """A weighted, explainable detection rule.

    ``pattern`` is matched against the normalized text (lower-cased, de-obfuscated), except
    for the rule with id ``unicode.hidden_chars``, which is matched against the original text
    because normalization removes the characters it looks for. Patterns must use bounded
    quantifiers only. ``weight`` is in (0, 1]; ``applies_to`` lists the sources scanned.
    """

    id: str
    description: str
    pattern: re.Pattern[str]
    weight: float
    applies_to: frozenset[Source]

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise GuardError("invalid_config", "rule id must be a non-empty string")
        if not isinstance(self.pattern, re.Pattern):
            raise GuardError("invalid_config", "rule pattern must be a compiled regex")
        if not is_number(self.weight) or not 0.0 < self.weight <= 1.0:
            raise GuardError("invalid_config", "rule weight must be in (0, 1]")
        if not _valid_sources(self.applies_to):
            raise GuardError(
                "invalid_config",
                "rule applies_to must be a non-empty frozenset of 'input' and 'retrieved'",
            )


_QUOTE = r'\\{0,2}"'
_BODY = r"[^{}]{0,400}"


def _json_key(name: str) -> str:
    return _QUOTE + name + _QUOTE + r"\s{0,8}:"


_NAME = _json_key("name")
_ARGS = _json_key("arguments")
_TOOL_NAME_FIRST = r"\{" + _BODY + _NAME + _BODY + _ARGS
_TOOL_ARGS_FIRST = r"\{" + _BODY + _ARGS + _BODY + _NAME
_TOOL_ARGS_OBJECT = _ARGS + r"\s{0,8}\{" + _BODY + r"\}" + _BODY + _NAME
_TOOL_CALL = "|".join((_TOOL_NAME_FIRST, _TOOL_ARGS_FIRST, _TOOL_ARGS_OBJECT))

_OVERRIDE = (
    r"\b(?:ignore|disregard|forget)\b(?:\W{1,32}\w{1,30}){0,3}\W{1,32}"
    r"(?:previous|prior|above)\b\W{1,32}(?:instructions|rules|prompts?)\b"
)
_LEAK = (
    r"\b(?:reveal|print|repeat)\b\W{1,32}(?:(?:your|the)\W{1,32})?"
    r"(?:system[\W_]{1,8}prompts?|instructions)\b"
)
_ROLE = r"<\|im_start\|>|\[inst\]|<<sys>>|^[ \t]{0,8}(?:system|assistant)[ \t]{0,4}:"
_EXFIL = r"!?\[[^\[\]\n]{0,200}\]\([ \t]{0,4}<?[^\s)<>?]{1,500}\?[^\s)<>]{1,500}"
_BASE64 = r"[a-z0-9+/]{200,2000}={0,2}"
_HIDDEN = r"[\u200b-\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0020-\U000e007e]{1,64}"

DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        id="override.ignore_previous",
        description="Instruction override such as 'ignore all previous instructions'.",
        pattern=re.compile(_OVERRIDE, re.IGNORECASE),
        weight=0.6,
        applies_to=_BOTH,
    ),
    Rule(
        id="leak.system_prompt",
        description="Attempt to make the model reveal or repeat its system prompt.",
        pattern=re.compile(_LEAK, re.IGNORECASE),
        weight=0.5,
        applies_to=_BOTH,
    ),
    Rule(
        id="role.fake_marker",
        description="Forged chat-template or role marker.",
        pattern=re.compile(_ROLE, re.IGNORECASE | re.MULTILINE),
        weight=0.3,
        applies_to=_BOTH,
    ),
    Rule(
        id="exfil.markdown_url",
        description="Markdown image or link whose URL carries a query string.",
        pattern=re.compile(_EXFIL, re.IGNORECASE),
        weight=0.5,
        applies_to=_RETRIEVED_ONLY,
    ),
    Rule(
        id="tool.forged_call",
        description="JSON object that looks like a forged tool call (name and arguments).",
        pattern=re.compile(_TOOL_CALL, re.IGNORECASE),
        weight=0.4,
        applies_to=_BOTH,
    ),
    Rule(
        id="encoding.base64_blob",
        description="Base64 run of at least 200 characters.",
        pattern=re.compile(_BASE64, re.IGNORECASE),
        weight=0.3,
        applies_to=_BOTH,
    ),
    Rule(
        id=HIDDEN_CHARS_RULE_ID,
        description="Zero-width, bidi control or Unicode tag characters removed by normalization.",
        pattern=re.compile(_HIDDEN),
        weight=0.4,
        applies_to=_BOTH,
    ),
)
