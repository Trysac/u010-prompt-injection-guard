"""Typed errors raised by the prompt injection guard."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["input_too_large", "invalid_config", "classifier_contract"]

_MAX_MESSAGE_CHARS = 200


class GuardError(ValueError):
    """Base class of every error raised by this library.

    The ``code`` attribute is stable and machine readable. Messages are truncated to 200
    characters and never contain the scanned text.
    """

    code: ErrorCode

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message[:_MAX_MESSAGE_CHARS])
        self.code = code
