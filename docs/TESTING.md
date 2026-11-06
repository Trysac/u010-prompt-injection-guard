# Testing

## Running

```sh
uv run pytest --cov=prompt_injection_guard   # tests with coverage report
uv run python scripts/check.py               # every gate, as CI and the factory run it
```

## Policy

- Branch coverage of `src/prompt_injection_guard` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import prompt_injection_guard`) and assert observable effects: return values, raised exceptions and their codes.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: no network, no wall clock, no dependence on test order.

## Layout

- `tests/test_prompt_injection_guard.cpython-312-pytest-9.2.0.pyc` is the only test module present in the repository snapshot. It is a compiled cache file, and its source `tests/test_prompt_injection_guard.py` covers the public API exports, default rule shape, bounded quantifiers in the default patterns, the override and leak blocking case with a classifier-free score, zero-width, fullwidth and Cyrillic confusable obfuscation, and the classifier score contract.
- `tests/fixtures/benign.txt` holds benign lines that must score below the review threshold.
