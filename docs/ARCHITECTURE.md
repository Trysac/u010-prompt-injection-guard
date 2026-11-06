# Architecture

## Purpose

`trysac-prompt-injection-guard` is a small, dependency-free Python library that screens untrusted text for prompt injection. It normalizes Unicode obfuscation, applies weighted explainable rules and optionally combines a caller-supplied classifier that can only raise the score.

## Shape

```text
caller code --> prompt_injection_guard (public API in __init__.py)
                    |
                    +-- errors.py      GuardError (code, message)
                    +-- normalize.py   per-code-point normalization with offset map
                    +-- rules.py       Rule model and DEFAULT_RULES
                    +-- scanner.py     GuardConfig, scan(), scoring, verdicts
```

- **Public API**: the names listed in `__all__` of `src/prompt_injection_guard/__init__.py`: `DEFAULT_RULES`, `ClassifierPort`, `Finding`, `GuardConfig`, `GuardError`, `Rule`, `ScanResult`, `scan`, `__version__`.
- **Normalization**: builds a matching copy of the text plus, for each character, the start and end offset in the original text, so findings refer to the original.
- **Matching**: each rule's pattern runs on the normalized text, except `unicode.hidden_chars`, which runs on the original text.
- **Errors**: `GuardError` (a `ValueError` subclass) carries a stable `code`.
- **Side effects**: none beyond a debug log line through a `NullHandler`; the library never configures logging and never logs input text.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
