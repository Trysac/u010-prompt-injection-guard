"""Offline first-line screen for prompt injection in user input and retrieved content.

``scan`` normalizes obfuscation, applies weighted explainable rules and optionally combines a
caller-supplied classifier that can only raise the score.

Threat model
============

Defended (one test per item):

* the seven rule families: instruction override, system prompt leak, fake role markers,
  markdown exfiltration links (retrieved content only), forged tool calls, base64 blobs and
  hidden Unicode characters;
* zero-width characters, bidi controls (Trojan Source, CVE-2021-42574) and Unicode tag
  characters (ASCII smuggling);
* fullwidth forms (NFKC) and the bundled subset of Unicode TR39 confusables;
* ReDoS (every pattern uses bounded quantifiers) and oversize input (fails closed).

Not defended: paraphrased, non-English, multi-turn, image or split payloads. This is a
screen, not a security boundary: never rely on it alone to protect a model or its tools.

The library never configures logging and never logs input text.
"""

from __future__ import annotations

from .errors import GuardError
from .rules import DEFAULT_RULES, Rule
from .scanner import ClassifierPort, Finding, GuardConfig, ScanResult, scan

__all__ = [
    "DEFAULT_RULES",
    "ClassifierPort",
    "Finding",
    "GuardConfig",
    "GuardError",
    "Rule",
    "ScanResult",
    "__version__",
    "scan",
]

__version__ = "0.1.0"
