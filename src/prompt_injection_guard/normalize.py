"""Obfuscation-resistant normalization with a map back to original offsets."""

from __future__ import annotations

import unicodedata
from array import array
from dataclasses import dataclass

from .errors import GuardError

_DEFAULT_MAX_CHARS = 200_000

_TAG_FIRST = 0xE0020
_TAG_LAST = 0xE007E
_TAG_OFFSET = 0xE0000

# Bundled subset of Unicode TR39 confusables.txt: exactly these rows and nothing else.
_CONFUSABLES: dict[int, str] = {
    0x0430: "a",  # Cyrillic a
    0x0441: "c",  # Cyrillic es
    0x0435: "e",  # Cyrillic ie
    0x0456: "i",  # Cyrillic byelorussian-ukrainian i
    0x043E: "o",  # Cyrillic o
    0x0440: "p",  # Cyrillic er
    0x0445: "x",  # Cyrillic ha
    0x0443: "y",  # Cyrillic u
    0x03BF: "o",  # Greek omicron
    0x03C1: "p",  # Greek rho
}


def _build_removed() -> frozenset[str]:
    codes = [0x2060, 0xFEFF]
    codes.extend(range(0x200B, 0x200E))  # zero-width space, non-joiner, joiner
    codes.extend(range(0x202A, 0x202F))  # bidi embeddings, overrides, pop (Trojan Source)
    codes.extend(range(0x2066, 0x206A))  # bidi isolates (Trojan Source)
    return frozenset(chr(code) for code in codes)


_REMOVED = _build_removed()


@dataclass(frozen=True)
class NormalizedText:
    """Matching copy of a text plus the original span of each of its characters.

    ``starts[i]`` and ``ends[i]`` are the offsets, in the original text, of the code point
    that produced character ``i`` of ``text``.
    """

    text: str
    starts: array[int]
    ends: array[int]


def normalize(text: str, max_chars: int = _DEFAULT_MAX_CHARS) -> NormalizedText:
    """Build the matching copy of ``text``.

    Per code point: NFKC, removal of zero-width and bidi control characters, mapping of tag
    characters U+E0020 to U+E007E to ASCII, the bundled confusable subset, then casefold.

    Raises:
        GuardError: with code ``input_too_large`` if ``text`` is longer than ``max_chars``.
    """
    if len(text) > max_chars:
        raise GuardError("input_too_large", f"text exceeds max_chars={max_chars}")
    pieces: list[str] = []
    starts: array[int] = array("L")
    ends: array[int] = array("L")
    for index, char in enumerate(text):
        code = ord(char)
        if code < 0x80:
            piece = char.lower()
        elif char in _REMOVED:
            continue
        else:
            source = chr(code - _TAG_OFFSET) if _TAG_FIRST <= code <= _TAG_LAST else char
            piece = unicodedata.normalize("NFKC", source).translate(_CONFUSABLES).casefold()
        pieces.append(piece)
        for _ in piece:
            starts.append(index)
            ends.append(index + 1)
    return NormalizedText("".join(pieces), starts, ends)
