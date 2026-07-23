"""Shared decode/normalize variant builder for content-inspecting guards.

Several guards (InputSanitizer, ExternalDataGuard, MultiModalGuard) need to
re-scan content after undoing common obfuscation - URL-encoding, hex,
base64, ROT13, string-reversal, zero-width/bidi-control insertion, and
Cyrillic homoglyph substitution - since attackers can wrap a payload in any
of these (or layer them) to evade pattern matching against the raw string
alone. This module is the single place that logic lives, so a fix to the
decode chain applies to every guard that uses it instead of drifting across
separate copies. Mirrors the npm sibling's src/decode-variants.ts exactly.
"""

import base64 as _b64
import binascii
import codecs
import re
from urllib.parse import unquote

_HOMOGLYPH_TRANS = str.maketrans("аеіоруАЕІОРУ", "aeiopyAEIOPY")

# Zero-width and bidi-control characters - ZWSP/ZWNJ/ZWJ/LRM/RLM (U+200B-200F),
# bidi embeddings/overrides (U+202A-202E), bidi isolates (U+2066-2069), word
# joiner (U+2060), Mongolian vowel separator (U+180E), BOM (U+FEFF), soft
# hyphen (U+00AD) - used to split a trigger word across invisible boundaries.
_INVISIBLE_CHARS_RE = re.compile(
    "[​-‏‪-‮⁦-⁩⁠᠎﻿­]"
)

# Some cap is still worth keeping as defense-in-depth against any
# not-yet-found catastrophic-backtracking regex elsewhere in the codebase
# (this function turns ONE pattern-scan into up to 40), but a cap below a
# guard's own max_content_length is a silent detection bypass, not safety -
# content between the two thresholds is neither decoded nor rejected for
# size. Must exceed every guard's default max_content_length (largest is
# ExternalDataGuard's 50,000). Deliberately lower than the npm sibling's
# equivalent cap (100,000): InputSanitizer's 170+ patterns run against
# CPython's slower regex engine, so matching npm's value costs ~770ms
# worst-case here vs npm's ~30ms — 65,000 (15,000 headroom above the 50,000
# threshold) keeps worst-case latency around 300ms while still closing the
# same bypass. Every guard pattern still scans linearly (not
# quadratically) at this size - see CHANGELOG's ReDoS hardening entry.
_MAX_INPUT_LENGTH = 65_000
_MAX_DEPTH = 3
_MAX_VARIANTS = 40


def _apply_one_step_transforms(text: str) -> list:
    """Single-pass decode/normalize transforms - each returns [] if inapplicable."""
    out = []

    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    if stripped != text:
        out.append(stripped)

    if "%" in text:
        try:
            d = unquote(text.replace("+", " "))
            if d != text:
                out.append(d)
        except Exception:
            pass

    hex_s = re.sub(r"\s", "", text)
    if len(hex_s) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", hex_s):
        try:
            # errors="replace" (not "strict") to match the npm sibling's
            # Buffer.toString('utf-8'), which never throws on invalid bytes
            # — a single stray non-UTF-8 byte (e.g. a Latin-1 smart quote)
            # mixed into an otherwise-plain payload must not silently drop
            # the whole decoded variant.
            d = binascii.unhexlify(hex_s).decode("utf-8", errors="replace")
            if d != text:
                out.append(d)
        except Exception:
            pass

    b64_s = re.sub(r"\s", "", text)
    if len(b64_s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+=*", b64_s):
        try:
            d = _b64.b64decode(b64_s + "==").decode("utf-8", errors="replace")
            if d != text:
                out.append(d)
        except Exception:
            pass

    rev = text[::-1]
    if rev != text:
        out.append(rev)

    try:
        rotated = codecs.encode(text, "rot_13")
        if rotated != text:
            out.append(rotated)
    except Exception:
        pass

    normed = text.translate(_HOMOGLYPH_TRANS)
    if normed != text:
        out.append(normed)

    return out


def build_decode_variants(raw_text: str) -> list:
    """Build de-obfuscated variants of `text` for re-scanning, chaining
    transforms up to a small depth so layered encodings (e.g. homograph
    substitution that is then percent-encoded, or hex-of-base64) resolve to
    readable text - a single independent pass per transform misses these
    combinations. Does not include the original `text` in the result.
    """
    text = raw_text[:_MAX_INPUT_LENGTH] if len(raw_text) > _MAX_INPUT_LENGTH else raw_text
    seen = {text}
    frontier = [text]
    depth = 0
    while depth < _MAX_DEPTH and len(seen) < _MAX_VARIANTS:
        next_frontier = []
        for variant in frontier:
            for t in _apply_one_step_transforms(variant):
                if t not in seen:
                    seen.add(t)
                    next_frontier.append(t)
                    if len(seen) >= _MAX_VARIANTS:
                        break
            if len(seen) >= _MAX_VARIANTS:
                break
        frontier = next_frontier
        if not frontier:
            break
        depth += 1
    seen.discard(text)
    return list(seen)
