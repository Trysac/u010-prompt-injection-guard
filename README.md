# prompt-injection-guard

[![PyPI version](https://img.shields.io/pypi/v/trysac-prompt-injection-guard)](https://pypi.org/project/trysac-prompt-injection-guard/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-prompt-injection-guard)](LICENSE)
[![CI](https://github.com/Trysac/u010-prompt-injection-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u010-prompt-injection-guard/actions/workflows/ci.yml)

Screen user input and retrieved content for prompt injection with explainable rules, Unicode obfuscation removal including tag characters, and an optional classifier that can only raise the score

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-prompt-injection-guard
# or
uv add trysac-prompt-injection-guard
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import prompt_injection_guard

# normalize() trims surrounding whitespace and lower-cases the text.
print(prompt_injection_guard.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    prompt_injection_guard.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
