from __future__ import annotations

import hashlib
import json
from pathlib import Path

from revenginstr.family.features import (
    MINHASH_PRIME,
    HashProfile,
    family_feature_set,
    minhash_signature,
    portable_pcode,
)
from revenginstr.family.mine import mine_dataset


def legacy_signature(
    features: set[str] | frozenset[str], person: bytes, permutation_prefix: str
) -> tuple[int, ...]:
    hashes = [
        int.from_bytes(
            hashlib.blake2b(token.encode("utf-8"), digest_size=8, person=person).digest(),
            "big",
        ) & MINHASH_PRIME
        for token in features
    ] or [0]
    result = []
    for index in range(32):
        digest = hashlib.sha256(f"{permutation_prefix}{index}".encode("ascii")).digest()
        a = (int.from_bytes(digest[:8], "big") % (MINHASH_PRIME - 1)) + 1
        b = int.from_bytes(digest[8:16], "big") % MINHASH_PRIME
        result.append(min((a * value + b) % MINHASH_PRIME for value in hashes))
    return tuple(result)


def text(op: str, constant: int = 4) -> str:
    return (
        "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\n"
        f"o0 {op} out=v0:4 in=reg:4 in=const:small:0x{constant:x}:4\n"
        "o1 RETURN ret=v0:4\n"
    )


def write_split(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_custom_hash_profile_reproduces_caller_owned_seeds() -> None:
    features = family_feature_set(text("INT_ADD"))
    profile = HashProfile("fixture-v1", b"FIXTURE", "FixtureFamilyMinHash/")
    assert minhash_signature(features, profile) == legacy_signature(
        features, b"FIXTURE", "FixtureFamilyMinHash/"
    )
    assert minhash_signature(features, "revenginstr-v1") != minhash_signature(features, profile)


def test_consumer_owned_hash_profile_and_format(tmp_path: Path) -> None:
    profile = HashProfile("consumer-v1", b"CONSUMER", "ConsumerFamilyMinHash/")
    features = family_feature_set(text("INT_ADD"))
    assert minhash_signature(features, profile) == legacy_signature(
        features, b"CONSUMER", "ConsumerFamilyMinHash/"
    )

    dataset = tmp_path / "dataset"
    dataset.mkdir()
    write_split(dataset / "train.jsonl", [{"id": "a", "text": text("INT_ADD")}])
    write_split(dataset / "validation.jsonl", [])
    write_split(dataset / "test.jsonl", [])
    output = tmp_path / "families.jsonl"
    report = mine_dataset(
        dataset, output, hash_profile=profile, output_format="CONSUMER.FunctionFamilies/1"
    )
    row = json.loads(output.read_text(encoding="utf-8"))
    assert row["format"] == "CONSUMER.FunctionFamilies/1"
    assert report["format"] == "CONSUMER.FunctionFamilies/1"
    assert report["policy"]["hash_profile"] == "consumer-v1"


def test_portable_pcode_ignores_headers_and_ssa_ordinals() -> None:
    left = text("INT_ADD", 4)
    right = left.replace("ARCH=X8632", "ARCH=ARM32").replace("v0:4", "v17:4")
    assert portable_pcode(left) == portable_pcode(right)


def test_family_miner_groups_exact_portable_duplicates(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    write_split(dataset / "train.jsonl", [
        {"id": "a", "text": text("INT_ADD"), "labels": {"domain": "game"}},
        {"id": "b", "text": text("INT_ADD").replace("ARCH=X8632", "ARCH=ARM32"), "labels": {"domain": "game"}},
    ])
    write_split(dataset / "validation.jsonl", [
        {"id": "c", "text": text("INT_SUB"), "labels": {"domain": "engine"}},
    ])
    write_split(dataset / "test.jsonl", [])
    output = tmp_path / "families.jsonl"
    report = mine_dataset(dataset, output)
    rows = {row["id"]: row for row in map(json.loads, output.read_text(encoding="utf-8").splitlines())}
    assert rows["a"]["family_id"] == rows["b"]["family_id"]
    assert rows["a"]["family_size"] == 2
    assert report["functions"] == 3
    assert report["policy"]["hash_profile"] == "revenginstr-v1"
