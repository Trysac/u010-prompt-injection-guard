# Security

`trysac-prompt-injection-guard` is a fast, offline first-line **screen** for prompt injection (OWASP LLM01:2025). It explains why a text was flagged. It is **not a security boundary**: never rely on it alone to protect a model, its tools or its data.

## Threat model

Untrusted text from users, web pages and documents is fed into prompts. Attackers try to override instructions, leak the system prompt, forge chat roles or tool calls, smuggle data out through markdown links, and hide all of that behind Unicode tricks.

### Defended

| Item | How |
|---|---|
| Instruction override | `override.ignore_previous` (weight 0.6) |
| System prompt leak | `leak.system_prompt` (0.5) |
| Fake role markers | `role.fake_marker` (0.3): `<\|im_start\|>`, `[INST]`, `<<SYS>>`, lines starting with `system:` or `assistant:` |
| Markdown exfiltration | `exfil.markdown_url` (0.5), only for `source="retrieved"`; URL must carry a query string |
| Forged tool calls | `tool.forged_call` (0.4): JSON object with `name` and `arguments` keys |
| Encoded payloads | `encoding.base64_blob` (0.3): base64 run of at least 200 characters |
| Hidden characters | `unicode.hidden_chars` (0.4): zero-width, bidi control or tag characters present in the original text |
| Zero-width characters | U+200B to U+200D, U+2060, U+FEFF are removed before matching |
| Bidi controls | U+202A to U+202E and U+2066 to U+2069 (Trojan Source, CVE-2021-42574) are removed before matching |
| Tag characters | U+E0020 to U+E007E are decoded to ASCII (ASCII smuggling) |
| Fullwidth forms | per code point NFKC |
| Listed confusables | Cyrillic a, c, e, i, o, p, x, y and Greek omicron, rho (bundled subset of Unicode TR39) |
| ReDoS | every pattern uses bounded quantifiers only |
| Oversize input | more than `max_chars` (default 200,000) raises `GuardError` with code `input_too_large` (fails closed) |

NFKC and confusable mapping alone never fire `unicode.hidden_chars`; only removed zero-width or bidi characters and tag characters do.

### Not defended

- Paraphrased payloads, non-English payloads, multi-turn attacks, image payloads and payloads split across several inputs.
- Confusables outside the bundled ten-entry list (for example uppercase Cyrillic letters).
- Anything that needs a model: a `ClassifierPort` can be plugged in, but it can raise the score and never lower it.
- Output filtering.

### Known false positives

`unicode.hidden_chars` fires on any zero-width joiner or byte order mark, including those in legitimate emoji sequences or files. This is intentional; the rule alone scores 0.4, which is a review verdict.

## Scoring

`rule_score = 1 - product(1 - weight)` over distinct fired rules. With a classifier score `c`, `score = 1 - (1 - rule_score) * (1 - classifier_weight * c)`. Verdict: `block` when the score is at least `block_threshold` (0.7), `review` when at least `review_threshold` (0.4), else `allow`. A 1e-12 tolerance avoids float rounding flips at the thresholds.

## Privacy and logging

The library never configures logging (it only installs a `NullHandler`) and never logs input text. The `on_event` payload contains the verdict, score, rule ids, source and text length only. Error messages never contain the scanned text. Findings contain an excerpt of at most 80 characters of the original text; treat them as sensitive.

## Reporting a vulnerability

See the repository `SECURITY.md`.
