"""Recover bounded structural roots from exact High-P-code def-use tokens."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ghidra_indirect_call_evidence import FORMAT_V2, FORMAT_V3, FORMAT_V4, validate_row

FORMAT = "REVENGINSTR.PointerProvenance/1"
FLOW_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
ROOT_V1 = "REVENGINSTR.GhidraCallerArgumentParameterRoot/1"
ROOT_V2 = "REVENGINSTR.GhidraCallerArgumentParameterRoot/2"
FLOW_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
ROOT_HEADER_V1 = (
    "format", "plan_id", "callee_entry", "parameter_index", "caller_entry",
    "caller_call_site", "caller_parameter_index", "argument_node_id", "status",
)
ROOT_HEADER_V2 = (
    "format", "plan_id", "callee_entry", "parameter_index", "caller_entry",
    "caller_call_site", "caller_parameter_index", "caller_parameter_offset_bytes",
    "argument_node_id", "status",
)
ADDRESS_RE = re.compile(r"^(?:(?P<space>[A-Za-z_$][\w$]*):)?(?:0x)?(?P<offset>[0-9a-fA-F]+)$")
DEF_TOKEN_RE = re.compile(r"^def:(?P<address>.+):(?P<time>[0-9]+):(?P<size>[0-9]+)$")
CALL_TARGET_DEF_RE = re.compile(r"^def:(?P<opcode>[A-Z_]+)@(?P<address>.+):(?P<time>[0-9]+):(?P<size>[0-9]+)$")
VALUE_TOKEN_RE = re.compile(r"^(?P<kind>[a-z_]+):(?P<value>.+):(?P<size>[0-9]+)$")
OFFSET_RE = re.compile(r"^(?:0x(?:0|[1-9a-f][0-9a-f]*)|-0x[1-9a-f][0-9a-f]*)$")
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_ALTERNATIVES = 16
DEFAULT_MAX_OPERATIONS = 1_000_000


@dataclass(frozen=True)
class Operation:
    function_entry: str
    function_key: str
    address: str
    address_key: str
    time: int
    opcode: str
    output: str
    inputs: tuple[str, ...]
    callee_entry: str
    source: dict[str, Any]


@dataclass(frozen=True)
class Step:
    address: str
    time: int
    opcode: str

    def record(self) -> dict[str, Any]:
        return {
            "operation_address": self.address,
            "operation_time": self.time,
            "opcode": self.opcode,
        }


@dataclass(frozen=True)
class Alternative:
    root_kind: str
    root_id: str
    offset: int | None
    pointer_size: int | None
    address_space_token: str | None
    status: str
    path: tuple[Step, ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _address_key(value: str, where: str) -> str:
    match = ADDRESS_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"{where}: unsupported address {value!r}")
    space = match.group("space")
    return f"{space.lower() + ':' if space else ''}0x{int(match.group('offset'), 16):x}"


def _source(path: Path, artifact_sha256: str, record_index: int, source_format: str) -> dict[str, Any]:
    return {
        "source_format": source_format,
        "artifact_path": str(path),
        "artifact_sha256": artifact_sha256,
        "record_index": record_index,
    }


def _parse_token(token: str, where: str) -> tuple[str, str, int]:
    match = DEF_TOKEN_RE.fullmatch(token)
    if match is not None:
        size = int(match.group("size"))
        if size < 1:
            raise ValueError(f"{where}: token size must be positive")
        address = _address_key(match.group("address"), where)
        return "def", f"{address}:{int(match.group('time'))}", size
    match = VALUE_TOKEN_RE.fullmatch(token)
    if match is None:
        raise ValueError(f"{where}: malformed varnode token {token!r}")
    kind, value, size_text = match.group("kind", "value", "size")
    size = int(size_text)
    if size < 1:
        raise ValueError(f"{where}: token size must be positive")
    if kind == "const":
        if not re.fullmatch(r"0x[0-9a-fA-F]+", value):
            raise ValueError(f"{where}: malformed constant token {token!r}")
        number = int(value, 16)
        if number >= 1 << (size * 8):
            raise ValueError(f"{where}: constant does not fit token width")
    elif kind not in {"register", "unique", "address", "input"}:
        raise ValueError(f"{where}: unsupported varnode token kind {kind!r}")
    return kind, value, size


def _signed_constant(token: str, where: str) -> tuple[int, int]:
    kind, value, size = _parse_token(token, where)
    if kind != "const":
        raise ValueError(f"{where}: expected a literal P-code constant")
    number = int(value, 16)
    sign_bit = 1 << (size * 8 - 1)
    return (number - (1 << (size * 8)) if number & sign_bit else number), size


def read_flows(
    paths: list[Path], *, max_operations: int = DEFAULT_MAX_OPERATIONS,
) -> tuple[dict[str, list[Operation]], dict[tuple[str, str, int], Operation]]:
    if not paths:
        raise ValueError("at least one P-code flow TSV is required")
    if max_operations < 1:
        raise ValueError("max_operations must be positive")
    functions: dict[str, list[Operation]] = defaultdict(list)
    operations: dict[tuple[str, str, int], Operation] = {}
    for path in paths:
        digest = _sha256(path)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t", strict=True)
            if tuple(reader.fieldnames or ()) != FLOW_HEADER:
                raise ValueError(f"{path}: expected the exact {FLOW_FORMAT} columns")
            for record_index, row in enumerate(reader, 1):
                where = f"{path}:data-row-{record_index}"
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"{where}: malformed TSV record")
                function_entry = row["function_entry"]
                function_key = _address_key(function_entry, f"{where}: function_entry")
                address = row["op_address"]
                address_key = _address_key(address, f"{where}: op_address")
                time_text = row["op_time"]
                if not time_text.isascii() or not time_text.isdecimal():
                    raise ValueError(f"{where}: op_time must be a non-negative decimal integer")
                opcode = row["opcode"]
                if not opcode:
                    raise ValueError(f"{where}: opcode must be non-empty")
                raw_inputs = row["inputs"]
                inputs = () if raw_inputs == "-" else tuple(raw_inputs.split(";"))
                if any(not token for token in inputs):
                    raise ValueError(f"{where}: malformed inputs cell")
                for token in inputs:
                    _parse_token(token, where)
                operation = Operation(
                    function_entry=function_entry,
                    function_key=function_key,
                    address=address,
                    address_key=address_key,
                    time=int(time_text),
                    opcode=opcode,
                    output=row["output"],
                    inputs=inputs,
                    callee_entry=row["callee_entry"],
                    source=_source(path, digest, record_index, FLOW_FORMAT),
                )
                key = (function_key, address_key, operation.time)
                if key in operations:
                    raise ValueError(f"{where}: duplicate operation identity {key!r}")
                if len(operations) >= max_operations:
                    raise ValueError(f"P-code operation budget exceeded: {max_operations}")
                operations[key] = operation
                functions[function_key].append(operation)
                if not operation.output:
                    raise ValueError(f"{where}: output cell must be '-' or a definition token")
                if operation.output != "-":
                    kind, definition_key, _ = _parse_token(operation.output, where)
                    if kind != "def":
                        raise ValueError(f"{where}: output must be a definition token")
                    definition_address, definition_time = definition_key.rsplit(":", 1)
                    if (definition_address, int(definition_time)) != (address_key, operation.time):
                        raise ValueError(f"{where}: output token does not identify its operation")
    for function_rows in functions.values():
        function_rows.sort(key=lambda operation: (operation.time, operation.address_key))
    return functions, operations


def read_callind_targets(
    paths: list[Path],
    operations: dict[tuple[str, str, int], Operation],
) -> dict[str, list[tuple[Operation, str, dict[str, Any]]]]:
    targets: dict[str, list[tuple[Operation, str, dict[str, Any]]]] = defaultdict(list)
    seen: set[tuple[str, str, int]] = set()
    program_identity = None
    for path in paths:
        digest = _sha256(path)
        with path.open("r", encoding="utf-8", newline="") as handle:
            for line_no, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw, object_pairs_hook=_unique_object)
                except ValueError as error:
                    raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
                where = f"{path}:{line_no}"
                source_format = validate_row(row, where)
                if source_format in {FORMAT_V2, FORMAT_V3, FORMAT_V4}:
                    identity = (row["program"], row["program_sha256"], row["architecture"])
                    if program_identity is not None and program_identity != identity:
                        raise ValueError(f"{where}: mixed binary identities in indirect-call evidence")
                    program_identity = identity
                function_key = _address_key(row["function_entry"], f"{where}: function_entry")
                call_key = _address_key(row["call_address"], f"{where}: call_address")
                site_identity = (function_key, call_key, row["call_time"])
                if site_identity in seen:
                    raise ValueError(f"{where}: duplicate indirect-call target site {site_identity!r}")
                seen.add(site_identity)
                operation = operations.get(site_identity)
                if operation is None or operation.opcode != "CALLIND":
                    raise ValueError(f"{where}: no exact CALLIND P-code operation")
                if len(operation.inputs) != row["arg_count"]:
                    raise ValueError(f"{where}: arg_count disagrees with the exact CALLIND flow row")

                def_match = CALL_TARGET_DEF_RE.fullmatch(row["target"])
                if def_match is None:
                    token = row["target"]
                    _parse_token(token, where)
                else:
                    definition_address = _address_key(def_match.group("address"), where)
                    definition_time = int(def_match.group("time"))
                    definition = operations.get((function_key, definition_address, definition_time))
                    if (
                        definition is None
                        or definition.opcode != def_match.group("opcode")
                        or definition.output == "-"
                    ):
                        raise ValueError(f"{where}: indirect-call target has no exact P-code definition")
                    _, _, size = _parse_token(definition.output, where)
                    if size != int(def_match.group("size")):
                        raise ValueError(f"{where}: indirect-call target width disagrees with its definition")
                    token = definition.output
                source = _source(path, digest, line_no, source_format)
                targets[function_key].append((operation, token, source))
    return targets


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _offset_value(text: str, where: str) -> int:
    if OFFSET_RE.fullmatch(text) is None:
        raise ValueError(f"{where}: invalid signed byte offset")
    sign = -1 if text.startswith("-") else 1
    digits = text[3:] if sign < 0 else text[2:]
    return sign * int(digits, 16)


def read_parameter_roots(
    path: Path,
    functions: dict[str, list[Operation]],
) -> dict[str, dict[str, list[Alternative]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: root TSV must be UTF-8") from error
    reader = csv.DictReader(text.splitlines(), delimiter="\t", strict=True)
    header = tuple(reader.fieldnames or ())
    if header == ROOT_HEADER_V1:
        version, fmt, expected_status = 1, ROOT_V1, "direct_parameter_root"
    elif header == ROOT_HEADER_V2:
        version, fmt, expected_status = 2, ROOT_V2, "constant_offset_parameter_root"
    else:
        raise ValueError(f"{path}: unsupported caller-parameter-root TSV header")

    calls: dict[tuple[str, str, str], list[Operation]] = defaultdict(list)
    for entry, rows in functions.items():
        for operation in rows:
            if operation.opcode == "CALL" and operation.callee_entry not in {"", "-"}:
                callee_key = _address_key(operation.callee_entry, "P-code callee_entry")
                calls[(entry, operation.address_key, callee_key)].append(operation)

    digest = hashlib.sha256(raw).hexdigest()
    seeds: dict[str, dict[str, list[Alternative]]] = defaultdict(lambda: defaultdict(list))
    for data_index, row in enumerate(reader, 1):
        where = f"{path}:{data_index + 1}"
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"{where}: malformed TSV record")
        if row["format"] != fmt or row["status"] != expected_status:
            raise ValueError(f"{where}: unsupported caller-parameter-root row")
        if not row["plan_id"] or not row["callee_entry"] or row["callee_entry"] == "-":
            raise ValueError(f"{where}: invalid plan or callee identity")
        if not row["caller_entry"] or not row["caller_call_site"] or row["caller_call_site"] == "-":
            raise ValueError(f"{where}: invalid caller identity")
        indices = (row["parameter_index"], row["caller_parameter_index"], row["argument_node_id"])
        if any(not value.isascii() or not value.isdecimal() for value in indices):
            raise ValueError(f"{where}: root indices must be non-negative decimal strings")
        callee_parameter, caller_parameter, node_index = map(int, indices)
        if node_index != 0:
            raise ValueError(f"{where}: root row must identify argument node 0")
        caller_key = _address_key(row["caller_entry"], f"{where}: caller_entry")
        callee_key = _address_key(row["callee_entry"], f"{where}: callee_entry")
        call_key = _address_key(row["caller_call_site"], f"{where}: caller_call_site")
        if caller_key not in functions:
            continue
        matches = calls.get((caller_key, call_key, callee_key), [])
        if len(matches) != 1:
            raise ValueError(f"{where}: root row does not identify one exact P-code CALL")
        call = matches[0]
        if callee_parameter >= len(call.inputs):
            raise ValueError(f"{where}: callee parameter exceeds the P-code call arguments")
        token = call.inputs[callee_parameter]
        kind, _, pointer_size = _parse_token(token, where)
        if kind == "const":
            raise ValueError(f"{where}: constant call arguments cannot be formal pointer roots")
        offset = 0 if version == 1 else _offset_value(row["caller_parameter_offset_bytes"], where)
        low, high = -(1 << (pointer_size * 8 - 1)), (1 << (pointer_size * 8 - 1)) - 1
        if not low <= offset <= high:
            raise ValueError(f"{where}: caller parameter offset exceeds pointer width")
        evidence = _source(path, digest, data_index, fmt)
        seeds[caller_key][token].append(Alternative(
            root_kind="function_parameter",
            root_id=f"parameter:{caller_parameter}",
            offset=offset,
            pointer_size=pointer_size,
            address_space_token=None,
            status="resolved",
            evidence=(evidence,),
        ))
    return seeds


def _constant(token: str, where: str) -> int | None:
    if not token.startswith("const:"):
        return None
    return _signed_constant(token, where)[0]


def _unknown(token: str, status: str, size: int | None = None) -> Alternative:
    return Alternative("unknown", token or "unknown", None, size, None, status)


def _address_anchor(token: str, where: str) -> Alternative:
    kind, value, size = _parse_token(token, where)
    if kind == "const":
        return Alternative("address_anchor", token, 0, size, None, "resolved")
    if kind == "address":
        return Alternative("address_anchor", value, 0, size, value.split(":", 1)[0], "resolved")
    return _unknown(token, "unknown", size)


class _Analyzer:
    def __init__(
        self,
        function_entry: str,
        rows: list[Operation],
        seeds: dict[str, list[Alternative]],
        *,
        max_depth: int,
        max_alternatives: int,
    ) -> None:
        self.function_entry = function_entry
        self.function_key = rows[0].function_key if rows else ""
        self.rows = rows
        self.seeds = seeds
        self.max_depth = max_depth
        self.max_alternatives = max_alternatives
        self.memo: dict[tuple[str, int], list[Alternative]] = {}
        self.by_key = {
            (operation.function_key, operation.address_key, operation.time): operation
            for operation in rows
        }

    @staticmethod
    def _evidence_union(*groups: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
        result: dict[tuple[Any, ...], dict[str, Any]] = {}
        for group in groups:
            for item in group:
                key = (
                    item["source_format"], item["artifact_sha256"],
                    item["record_index"], item["artifact_path"],
                )
                result[key] = item
        return tuple(result[key] for key in sorted(result))

    def _step(self, operation: Operation) -> Step:
        return Step(operation.address, operation.time, operation.opcode)

    def _append(self, alternative: Alternative, operation: Operation) -> Alternative:
        return Alternative(
            alternative.root_kind, alternative.root_id, alternative.offset,
            alternative.pointer_size, alternative.address_space_token,
            alternative.status, alternative.path + (self._step(operation),),
            self._evidence_union(alternative.evidence, (operation.source,)),
        )

    def _bounded(self, alternatives: list[Alternative], token: str) -> list[Alternative]:
        unique: dict[tuple[Any, ...], Alternative] = {}
        for alternative in alternatives:
            key = (
                alternative.root_kind, alternative.root_id, alternative.offset,
                alternative.pointer_size, alternative.address_space_token,
                alternative.status, alternative.path,
            )
            previous = unique.get(key)
            if previous is None:
                unique[key] = alternative
            else:
                unique[key] = Alternative(
                    previous.root_kind, previous.root_id, previous.offset,
                    previous.pointer_size, previous.address_space_token,
                    previous.status, previous.path,
                    self._evidence_union(previous.evidence, alternative.evidence),
                )
        values = list(unique.values())
        values.sort(key=lambda item: (
            item.root_kind, item.root_id, item.offset if item.offset is not None else 0,
            item.status, tuple((step.address, step.time, step.opcode) for step in item.path),
        ))
        if len(values) > self.max_alternatives:
            evidence = self._evidence_union(*(value.evidence for value in values))
            return [Alternative("unknown", token, None, None, None, "alternative_limit", evidence=evidence)]
        return values

    def _constant_base(
        self, token: str, where: str, *, pointer_context: bool,
        depth: int = 0, active: set[str] | None = None,
    ) -> list[Alternative]:
        if pointer_context and token.startswith(("const:", "address:")):
            return [_address_anchor(token, where)]
        return self.resolve(token, depth, set() if active is None else active)

    def resolve(self, token: str, depth: int, active: set[str]) -> list[Alternative]:
        where = f"{self.function_entry}: {token}"
        if depth > self.max_depth:
            _, _, size = _parse_token(token, where)
            return [_unknown(token, "depth_limit", size)]
        seeded = self.seeds.get(token)
        if seeded:
            return self._bounded(list(seeded), token)
        kind, value, size = _parse_token(token, where)
        if kind == "const":
            return [_unknown(token, "unknown", size)]
        if kind != "def":
            return [_unknown(token, "unknown", size)]
        if token in active:
            return [_unknown(token, "cycle", size)]
        memo_key = (token, self.max_depth - depth)
        if memo_key in self.memo:
            return self.memo[memo_key]
        address_key, time_text = value.rsplit(":", 1)
        operation = self.by_key.get((self.function_key, address_key, int(time_text)))
        if operation is None or operation.output != token:
            return [_unknown(token, "missing_definition", size)]
        next_active = {*active, token}
        result = self._resolve_operation(operation, depth, next_active)
        result = self._bounded(result, token)
        self.memo[memo_key] = result
        return result

    def _offset(self, alternatives: list[Alternative], delta: int, operation: Operation) -> list[Alternative]:
        output_kind, _, output_size = _parse_token(operation.output, operation.address)
        if output_kind != "def":
            return [_unknown(operation.output, "unknown", output_size)]
        result: list[Alternative] = []
        for base in alternatives:
            if base.status not in {"resolved", "load_anchor"} or base.offset is None:
                result.append(self._append(Alternative(
                    base.root_kind, base.root_id, None, base.pointer_size,
                    base.address_space_token, base.status, base.path, base.evidence,
                ), operation))
                continue
            if base.pointer_size is not None and base.pointer_size != output_size:
                result.append(self._append(Alternative(
                    base.root_kind, base.root_id, None, base.pointer_size,
                    base.address_space_token, "width_mismatch", base.path, base.evidence,
                ), operation))
                continue
            low, high = -(1 << (output_size * 8 - 1)), (1 << (output_size * 8 - 1)) - 1
            offset = base.offset + delta
            if not low <= offset <= high:
                result.append(self._append(Alternative(
                    base.root_kind, base.root_id, None, output_size,
                    base.address_space_token, "offset_overflow", base.path, base.evidence,
                ), operation))
                continue
            result.append(self._append(Alternative(
                base.root_kind, base.root_id, offset, output_size,
                base.address_space_token, "resolved", base.path, base.evidence,
            ), operation))
        return self._bounded(result, operation.output)

    def _resolve_operation(self, operation: Operation, depth: int, active: set[str]) -> list[Alternative]:
        where = f"{self.function_entry}:{operation.address}#{operation.time}"
        inputs = operation.inputs
        if operation.opcode in {"COPY", "CAST"}:
            if len(inputs) != 1:
                return [_unknown(operation.output, "unsupported_opcode")]
            _, _, source_size = _parse_token(inputs[0], where)
            output_kind, _, output_size = _parse_token(operation.output, where)
            if output_kind != "def":
                return [_unknown(operation.output, "unknown", output_size)]
            if source_size != output_size:
                return [self._append(Alternative(
                    "unknown", operation.output, None, output_size, None,
                    "width_mismatch", evidence=(operation.source,),
                ), operation)]
            return [self._append(value, operation) for value in self.resolve(inputs[0], depth + 1, active)]

        if operation.opcode == "MULTIEQUAL":
            if not inputs:
                return [_unknown(operation.output, "unsupported_opcode")]
            values = [
                self._append(value, operation)
                for token in inputs
                for value in self.resolve(token, depth + 1, active)
            ]
            return self._bounded(values, operation.output)

        if operation.opcode in {"PTRADD", "PTRSUB", "INT_ADD", "INT_SUB"}:
            expected = 3 if operation.opcode == "PTRADD" else 2
            if len(inputs) != expected:
                return [_unknown(operation.output, "unsupported_opcode")]
            left_token, *rest = inputs
            base_token = rest[0] if operation.opcode == "INT_ADD" and left_token.startswith("const:") else left_token
            base = self._constant_base(
                base_token, where,
                pointer_context=operation.opcode in {"PTRADD", "PTRSUB"},
                depth=depth + 1, active=active,
            )
            output_kind, _, output_size = _parse_token(operation.output, where)
            _, _, base_size = _parse_token(base_token, where)
            if output_kind != "def" or base_size != output_size:
                return [self._append(Alternative(
                    item.root_kind, item.root_id, None, item.pointer_size,
                    item.address_space_token, "width_mismatch", item.path, item.evidence,
                ), operation) for item in base]
            if operation.opcode == "PTRADD":
                index = _constant(rest[0], where)
                scale = _constant(rest[1], where)
                if index is None or scale is None or scale < 0:
                    return [
                        self._append(Alternative(
                            item.root_kind, item.root_id, None, item.pointer_size,
                            item.address_space_token, "dynamic_offset", item.path, item.evidence,
                        ), operation) for item in base
                    ]
                delta = index * scale
            else:
                offset_token = left_token if base_token != left_token else rest[0]
                constant = _constant(offset_token, where)
                if constant is None:
                    return [self._append(Alternative(
                        item.root_kind, item.root_id, None, item.pointer_size,
                        item.address_space_token, "dynamic_offset", item.path, item.evidence,
                    ), operation) for item in base]
                delta = constant
                if operation.opcode == "INT_SUB":
                    delta = -delta
            return self._offset(base, delta, operation)

        if operation.opcode == "LOAD":
            if len(inputs) != 2:
                return [_unknown(operation.output, "unsupported_opcode")]
            output_kind, _, output_size = _parse_token(operation.output, where)
            if output_kind != "def":
                return [_unknown(operation.output, "unknown", output_size)]
            anchor = Alternative(
                "memory_read_anchor",
                f"memory:{operation.function_entry}:{operation.address}#{operation.time}",
                0, output_size, inputs[0], "load_anchor", (),
            )
            return [self._append(anchor, operation)]

        if operation.opcode == "INDIRECT":
            return [self._append(_unknown(operation.output, "indirect_barrier"), operation)]
        if operation.opcode in {"CALL", "CALLIND"}:
            return [self._append(_unknown(operation.output, "call_barrier"), operation)]
        if operation.opcode == "CALLOTHER":
            return [self._append(_unknown(operation.output, "indirect_barrier"), operation)]
        return [self._append(_unknown(operation.output, "unsupported_opcode"), operation)]

    def output_record(self, operation: Operation) -> dict[str, Any] | None:
        if operation.output == "-":
            return None
        alternatives = self.resolve(operation.output, 0, set())
        status = _status(alternatives)
        load_address: dict[str, Any] | None = None
        if operation.opcode == "LOAD" and len(operation.inputs) == 2:
            address_values = self._bounded(self._constant_base(
                operation.inputs[1], f"{self.function_entry}:{operation.address}#{operation.time}",
                pointer_context=True,
            ), operation.inputs[1])
            load_address = {
                "address_token": operation.inputs[1],
                "space_token": operation.inputs[0],
                "status": _status(address_values),
                "alternatives": [_alternative_record(item) for item in address_values],
            }
        return {
            "format": FORMAT,
            "record_kind": "operation_output",
            "evidence_class": "derived_structural",
            "program_id": self.program_id,
            "function_entry": operation.function_entry,
            "operation_address": operation.address,
            "operation_time": operation.time,
            "opcode": operation.opcode,
            "output_token": operation.output,
            "status": status,
            "alternatives": [_alternative_record(item) for item in alternatives],
            "load_address": load_address,
            "source": operation.source,
            "target_source": None,
        }

    def callind_target_record(
        self, operation: Operation, token: str, target_source: dict[str, Any],
    ) -> dict[str, Any]:
        where = f"{self.function_entry}:{operation.address}#{operation.time}: target"
        alternatives = (
            [_address_anchor(token, where)]
            if token.startswith(("const:", "address:"))
            else self.resolve(token, 0, set())
        )
        return {
            "format": FORMAT,
            "record_kind": "callind_target",
            "evidence_class": "derived_structural",
            "program_id": self.program_id,
            "function_entry": operation.function_entry,
            "operation_address": operation.address,
            "operation_time": operation.time,
            "opcode": operation.opcode,
            "output_token": token,
            "status": _status(alternatives),
            "alternatives": [_alternative_record(item) for item in alternatives],
            "load_address": None,
            "source": operation.source,
            "target_source": target_source,
        }

    def analyze(self, program_id: str) -> list[dict[str, Any]]:
        self.program_id = program_id
        return [record for operation in self.rows if (record := self.output_record(operation)) is not None]


def _alternative_record(alternative: Alternative) -> dict[str, Any]:
    return {
        "root_kind": alternative.root_kind,
        "evidence_class": "derived_structural",
        "root_id": alternative.root_id,
        "offset_bytes": alternative.offset,
        "pointer_size_bytes": alternative.pointer_size,
        "address_space_token": alternative.address_space_token,
        "status": alternative.status,
        "transformation_path": [step.record() for step in alternative.path],
        "evidence_refs": list(alternative.evidence),
    }


def _status(alternatives: list[Alternative]) -> str:
    if not alternatives:
        return "unknown"
    identities = {
        (value.root_kind, value.root_id, value.offset, value.status)
        for value in alternatives
    }
    if len(identities) > 1:
        return "ambiguous"
    return alternatives[0].status


def build_pointer_provenance(
    flow_paths: list[Path],
    *,
    program_id: str,
    parameter_roots_tsv: Path | None = None,
    callind_evidence_paths: list[Path] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_alternatives: int = DEFAULT_MAX_ALTERNATIVES,
    max_operations: int = DEFAULT_MAX_OPERATIONS,
) -> list[dict[str, Any]]:
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_depth < 1 or max_alternatives < 1 or max_operations < 1:
        raise ValueError("analysis budgets must be positive")
    functions, operations = read_flows(flow_paths, max_operations=max_operations)
    roots: dict[str, dict[str, list[Alternative]]] = defaultdict(lambda: defaultdict(list))
    if parameter_roots_tsv is not None:
        roots = read_parameter_roots(parameter_roots_tsv, functions)
    callind_targets = read_callind_targets(callind_evidence_paths or [], operations)
    result: list[dict[str, Any]] = []
    for function_key, operations in sorted(functions.items()):
        analyzer = _Analyzer(
            operations[0].function_entry, operations,
            roots.get(function_key, {}), max_depth=max_depth,
            max_alternatives=max_alternatives,
        )
        function_records = analyzer.analyze(program_id)
        function_records.extend(
            analyzer.callind_target_record(operation, token, source)
            for operation, token, source in callind_targets.get(function_key, [])
        )
        function_records.sort(key=lambda row: (
            row["operation_time"], row["record_kind"], row["operation_address"],
        ))
        result.extend(function_records)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--pcode-flow", type=Path, action="append", required=True)
    parser.add_argument("--parameter-roots", type=Path)
    parser.add_argument("--indirect-call-evidence", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-alternatives", type=int, default=DEFAULT_MAX_ALTERNATIVES)
    parser.add_argument("--max-operations", type=int, default=DEFAULT_MAX_OPERATIONS)
    args = parser.parse_args(argv)
    rows = build_pointer_provenance(
        args.pcode_flow, program_id=args.program_id,
        parameter_roots_tsv=args.parameter_roots, max_depth=args.max_depth,
        callind_evidence_paths=args.indirect_call_evidence,
        max_alternatives=args.max_alternatives, max_operations=args.max_operations,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("output rows:", len(rows))
    print("statuses:", dict(sorted(Counter(row["status"] for row in rows).items())))
    print("output:", args.output)
    return 0
