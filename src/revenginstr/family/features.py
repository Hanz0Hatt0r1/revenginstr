#!/usr/bin/env python3
"""Portable P-code normalization and structural function-family features."""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

_OP_LINE = re.compile(r"^o\d+\s+")
_SSA = re.compile(r"\bv\d+:(\d+)")
_SMALL_CONST = re.compile(r"const:small:0x([0-9a-fA-F]+):(\d+)")
_WIDTHED_ROLE = re.compile(r"\b(v|reg|input|mem|tmp|def:omitted):(\d+)")
_CONST_WIDTH = re.compile(r"\b(const:(?:tiny|small|medium|large|xlarge|zero|one|allones)):(\d+)")

MINHASH_SIZE = 32
MINHASH_PRIME = (1 << 61) - 1


@dataclass(frozen=True)
class HashProfile:
    """Caller-owned MinHash seed configuration."""

    name: str
    person: bytes
    permutation_prefix: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip() or self.name.strip() != self.name:
            raise ValueError("hash profile name must be a non-empty string without surrounding whitespace")
        if not isinstance(self.permutation_prefix, str) or not self.permutation_prefix:
            raise ValueError("hash profile name and permutation prefix must be non-empty")
        if not isinstance(self.person, bytes) or not self.person or len(self.person) > 16:
            raise ValueError("hash profile person must contain between 1 and 16 bytes")


PROFILES = {
    "revenginstr-v1": HashProfile(
        "revenginstr-v1", b"REVENG-FAM", "RevEngInstrFamilyMinHash/"
    ),
}


def bucket_small_constant(match: re.Match[str]) -> str:
    value = int(match.group(1), 16)
    size = match.group(2)
    if value <= 0x0F:
        bucket = "tiny"
    elif value <= 0x3F:
        bucket = "small"
    elif value <= 0xFF:
        bucket = "medium"
    elif value <= 0x3FF:
        bucket = "large"
    else:
        bucket = "xlarge"
    return f"const:{bucket}:{size}"


def portable_pcode(text: str) -> str:
    out: list[str] = []
    for raw in text.splitlines():
        if not _OP_LINE.match(raw):
            continue
        line = _OP_LINE.sub("OP ", raw, count=1)
        line = _SSA.sub(r"v:\1", line)
        line = _SMALL_CONST.sub(bucket_small_constant, line)
        out.append(line)
    return "\n".join(out)


def shape_line(line: str) -> str:
    line = _WIDTHED_ROLE.sub(lambda match: match.group(1), line)
    return _CONST_WIDTH.sub(lambda match: match.group(1), line)


def count_bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    lower, upper = 2, 3
    while upper < value and upper < 255:
        lower = upper + 1
        upper = (upper << 1) + 1
    return f"{lower}-{upper}" if value <= upper else "256+"


def family_feature_set(text: str) -> frozenset[str]:
    portable = portable_pcode(text)
    lines = [line for line in portable.splitlines() if line]
    if not lines:
        return frozenset({"empty"})
    signatures: list[str] = []
    features: set[str] = set()
    opcode_counts: Counter[str] = Counter()
    for line in lines:
        parts = line.split()
        opcode = parts[1] if len(parts) >= 2 else "UNKNOWN"
        call_kind = next((part for part in parts[2:] if part.startswith("call:")), "")
        signature = opcode if not call_kind else f"{opcode}:{call_kind}"
        signatures.append(signature)
        opcode_counts[signature] += 1
        features.add(f"shape:{shape_line(line)}")
        features.add(f"op:{signature}")
    for width in (2, 3, 4):
        for index in range(max(0, len(signatures) - width + 1)):
            features.add(f"seq{width}:" + "|".join(signatures[index:index + width]))
    for opcode, count in opcode_counts.items():
        features.add(f"count:{opcode}:{count_bucket(count)}")
    features.add(f"ops:{count_bucket(len(lines))}")
    return frozenset(features)


def jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    if not left and not right:
        return 1.0
    union = len(left | right)
    return len(left & right) / union if union else 1.0


def profile_config(profile: str | HashProfile) -> HashProfile:
    if isinstance(profile, HashProfile):
        return profile
    try:
        return PROFILES[profile]
    except KeyError as error:
        raise ValueError(f"unknown family hash profile: {profile}; choose from {sorted(PROFILES)}") from error


def hash64(value: str, profile: str | HashProfile = "revenginstr-v1") -> int:
    config = profile_config(profile)
    return int.from_bytes(
        hashlib.blake2b(value.encode("utf-8"), digest_size=8, person=config.person).digest(),
        "big",
    ) & MINHASH_PRIME


@lru_cache(maxsize=None)
def _profile_permutations(config: HashProfile) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for index in range(MINHASH_SIZE):
        digest = hashlib.sha256(f"{config.permutation_prefix}{index}".encode("ascii")).digest()
        a = (int.from_bytes(digest[:8], "big") % (MINHASH_PRIME - 1)) + 1
        b = int.from_bytes(digest[8:16], "big") % MINHASH_PRIME
        result.append((a, b))
    return tuple(result)


def permutations(profile: str | HashProfile = "revenginstr-v1") -> tuple[tuple[int, int], ...]:
    return _profile_permutations(profile_config(profile))


def minhash_signature(
    features: Iterable[str], profile: str | HashProfile = "revenginstr-v1"
) -> tuple[int, ...]:
    config = profile_config(profile)
    hashes = [hash64(token, config) for token in features]
    if not hashes:
        hashes = [0]
    return tuple(
        min((a * value + b) % MINHASH_PRIME for value in hashes)
        for a, b in permutations(config)
    )


def lsh_band_keys(signature: tuple[int, ...], bands: int = 8) -> tuple[tuple[int, ...], ...]:
    if bands <= 0 or len(signature) % bands:
        raise ValueError("signature length must divide evenly by bands")
    rows = len(signature) // bands
    return tuple(signature[index:index + rows] for index in range(0, len(signature), rows))
