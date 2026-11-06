# Rule-based prompt injection screen with offset-preserving normalization

Status: accepted (generated, pending human review)

## Context

Agents and RAG systems feed untrusted text into prompts (OWASP LLM01:2025). Existing tools such as LLM Guard or Rebuff need models or a service. Teams need a fast, offline, explainable first-line screen that resists common Unicode obfuscation (zero-width, bidi, tag characters, fullwidth, confusables) and still reports where in the original text something was found.

## Decision

Implement a zero-dependency library: weighted regex rules with bounded quantifiers applied to a normalized copy of the text that keeps an offset map back to the original. Scores combine by noisy-OR over distinct fired rules, and an optional classifier port can only raise the score. The unicode.hidden_chars rule is matched against the original text because normalization removes the characters it looks for. Oversize input and invalid configuration fail closed with a typed GuardError. The library installs only a NullHandler and never logs or emits input text.

## Consequences

The screen is fast, deterministic and explainable and needs no model or network. It does not detect paraphrased, non-English, multi-turn, image or split payloads, so it must not be used as a security boundary. Legitimate zero-width joiners or byte order marks raise a review-level score. The hidden-chars rule is special-cased by id in the scanner. Rule weights and the confusable subset are intentionally small and fixed, so extending them requires new rules or a follow-up decision.
