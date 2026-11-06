# Project record

## Objective

Provide a fast, offline, dependency-free first-line screen that flags prompt injection in user input and retrieved content, explains which rules fired, and can combine a caller-supplied classifier without ever lowering the rule-based score.

## Scope

- In scope: the public API documented in [README.md](../README.md): `scan()`, the seven default rules, the normalization of obfuscated text (NFKC, zero-width and bidi removal, tag-character decoding, a bundled subset of ten TR39 confusables), noisy-OR scoring, verdicts, size limit and typed errors.
- Out of scope: models or any classifier implementation, output filtering, languages other than the rule patterns cover, multi-turn or image payloads, and anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 417062 / 91465 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.7528 |

## Factory run u010 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2569 | 77187 | 0 | 4246 | 0.3889 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 352 | 5766 | 24462 | 0.0204 |
| fix-2 | claude-sonnet-5-5 | no | 4 | 483 | 6139 | 24585 | 0.0226 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 641 | 9800 | 43552 | 0.0353 |
| fix-4 | claude-sonnet-5-5 | no | 8 | 1098 | 8009 | 58077 | 0.0368 |
| audit | claude-sonnet-5-5 | no | 12 | 6052 | 38309 | 128690 | 0.1692 |
| docs | claude-haiku-5-5 | no | 130847 | 5652 | 0 | 0 | 0.0796 |

Total: $0.7528. Prices: Anthropic list prices.
