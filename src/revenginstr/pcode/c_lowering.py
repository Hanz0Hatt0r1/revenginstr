#!/usr/bin/env python3
"""Lower a fail-closed scalar P-code function subset to native C."""
from __future__ import annotations

import argparse
import bisect
import gzip
import hashlib
import json
from pathlib import Path
from typing import TextIO

CORPUS_FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1"
MANIFEST_FORMAT = "REVENGINSTR.GhidraFunctionInstructionCorpus/1"
SPACES_FORMAT = "REVENGINSTR.GhidraLanguageAddressSpaces/1"
MAX_UNIQUE_BYTES = 64 * 1024
MAX_SCALAR_BYTES = 8


class PcodeLoweringError(ValueError):
    """Raised when a function uses semantics outside the implemented subset."""


def _open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _hex(value: object, where: str) -> int:
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise ValueError(f"{where}: expected a hexadecimal offset")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid hexadecimal offset") from exc


def _size(node: dict, where: str) -> int:
    value = node.get("size")
    if type(value) is not int or value < 1:
        raise PcodeLoweringError(f"{where}: scalar lowering requires a positive varnode size")
    if value > MAX_SCALAR_BYTES and value != 10:
        raise PcodeLoweringError(f"{where}: scalar varnode size {value} exceeds {MAX_SCALAR_BYTES}-byte limit")
    return value


def _unique_layout_offset(node: dict, where: str, layout: list[tuple[int, int, int]]) -> int:
    source_offset = _hex(node.get("offset"), where)
    size = _size(node, where)
    index = bisect.bisect_right(layout, source_offset, key=lambda region: region[0]) - 1
    if index < 0:
        raise PcodeLoweringError(f"{where}: unique varnode is missing from its local layout")
    source_start, source_end, compact_start = layout[index]
    if source_offset + size > source_end:
        raise PcodeLoweringError(f"{where}: unique varnode crosses a local layout boundary")
    return compact_start + source_offset - source_start


def _varnode_offset(node: dict, where: str, unique_layout: list[tuple[int, int, int]]) -> int:
    if node.get("space") == "unique":
        return _unique_layout_offset(node, where, unique_layout)
    return _hex(node.get("offset"), where)


def _read_expr(
    node: dict, where: str, unique_layout: list[tuple[int, int, int]], big_endian: bool,
) -> tuple[list[str], str, int]:
    size = _size(node, where)
    if size == 10:
        raise PcodeLoweringError(f"{where}: 10-byte values require a binary80 or raw-byte operation")
    space = node.get("space")
    offset = _hex(node.get("offset"), where)
    if node.get("constant") is True and space == "const":
        return [], f"UINT64_C(0x{offset & ((1 << (size * 8)) - 1):x})", size
    if node.get("constant") is not False or not isinstance(space, str) or not space:
        raise PcodeLoweringError(f"{where}: invalid non-constant varnode")
    offset = _varnode_offset(node, where, unique_layout)
    return [
        f"uint64_t {where}_value;",
        f"if (rvi_read_value(ctx, _unique, UINT64_C(0), _unique_size, "
        f"{_escape_c_string(space)}, UINT64_C(0x{offset:x}), {size}, {_c_bool(big_endian)}, "
        f"&{where}_value) != 0) return -1;",
    ], f"{where}_value", size


def _escape_c_string(value: str) -> str:
    return json.dumps(value)


def _c_bool(value: bool) -> str:
    return "1" if value else "0"


def _direct_control_target(node: object, default_space: str, where: str) -> int:
    if not isinstance(node, dict):
        raise PcodeLoweringError(f"{where}: expected a direct control target varnode")
    if node.get("space") == default_space and node.get("constant") is False:
        return _hex(node.get("offset"), where)
    if node.get("space") == "const" and node.get("constant") is True:
        raise PcodeLoweringError(f"{where}: P-code-relative control targets are not supported")
    raise PcodeLoweringError(f"{where}: expected a direct {default_space} target")


def _pcode_relative_target(node: object, operation_index: int, where: str, operation_count: int) -> int:
    if not isinstance(node, dict) or node.get("space") != "const" or node.get("constant") is not True:
        raise PcodeLoweringError(f"{where}: expected a constant-space relative target")
    size = _size(node, where)
    value = _hex(node.get("offset"), where) & ((1 << (size * 8)) - 1)
    sign_bit = 1 << (size * 8 - 1)
    if value & sign_bit:
        value -= 1 << (size * 8)
    target = operation_index + value
    if not 0 <= target < operation_count:
        raise PcodeLoweringError(f"{where}: relative target leaves the current instruction's P-code")
    return target


def _write_output(
    node: dict, expr: str, where: str, unique_layout: list[tuple[int, int, int]], big_endian: bool,
) -> str:
    size = _size(node, where)
    if size == 10:
        raise PcodeLoweringError(f"{where}: 10-byte output requires a binary80 or raw-byte operation")
    if node.get("constant") is not False or not isinstance(node.get("space"), str):
        raise PcodeLoweringError(f"{where}: output must be a writable varnode")
    space = _escape_c_string(node["space"])
    offset = _varnode_offset(node, where, unique_layout)
    return (
        f"if (rvi_write_value(ctx, _unique, UINT64_C(0), _unique_size, "
        f"{space}, UINT64_C(0x{offset:x}), {size}, {_c_bool(big_endian)}, "
        f"({expr}) & rvi_mask({size})) != 0) return -1;"
    )


def _read_bytes_expr(
    node: dict, where: str, unique_layout: list[tuple[int, int, int]], big_endian: bool,
) -> tuple[list[str], str]:
    if _size(node, where) != 10:
        raise PcodeLoweringError(f"{where}: raw-byte operation requires a 10-byte varnode")
    name = where.replace("-", "_") + "_bytes"
    if node.get("space") == "const" and node.get("constant") is True:
        value = _hex(node.get("offset"), where) & ((1 << 80) - 1)
        byte_values = [(value >> (index * 8)) & 0xff for index in range(10)]
        if big_endian:
            byte_values.reverse()
        initializer = ", ".join(f"0x{byte:02x}" for byte in byte_values)
        return [f"uint8_t {name}[10] = {{{initializer}}};"], name
    if node.get("constant") is not False or not isinstance(node.get("space"), str):
        raise PcodeLoweringError(f"{where}: expected a constant or writable 10-byte varnode")
    offset = _varnode_offset(node, where, unique_layout)
    space = _escape_c_string(node["space"])
    return [
        f"uint8_t {name}[10];",
        f"if (rvi_read_bytes(ctx, _unique, UINT64_C(0), _unique_size, {space}, "
        f"UINT64_C(0x{offset:x}), 10, {name}) != 0) return -1;",
    ], name


def _write_bytes_output(
    node: dict, value: str, where: str, unique_layout: list[tuple[int, int, int]],
) -> str:
    if _size(node, where) != 10 or node.get("constant") is not False or not isinstance(node.get("space"), str):
        raise PcodeLoweringError(f"{where}: expected a writable 10-byte output")
    offset = _varnode_offset(node, where, unique_layout)
    space = _escape_c_string(node["space"])
    return (
        f"if (rvi_write_bytes(ctx, _unique, UINT64_C(0), _unique_size, {space}, "
        f"UINT64_C(0x{offset:x}), 10, {value}) != 0) return -1;"
    )


_BINARY = {
    "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
    "INT_AND": "&", "INT_OR": "|", "INT_XOR": "^",
}


def _lower_operation(
    operation: dict, location: str, sequence: int,
    unique_layout: list[tuple[int, int, int]], big_endian: bool, supports_binary80: bool,
) -> tuple[list[str], str | None]:
    opcode = operation.get("opcode")
    if not isinstance(opcode, str) or not opcode.strip():
        raise PcodeLoweringError(f"{location}: operation {sequence} has no opcode")
    opcode = opcode.strip().upper()
    inputs = operation.get("inputs")
    if not isinstance(inputs, list) or any(not isinstance(node, dict) for node in inputs):
        raise PcodeLoweringError(f"{location}: {opcode} inputs must be varnodes")
    output = operation.get("output")
    if output is not None and not isinstance(output, dict):
        raise PcodeLoweringError(f"{location}: {opcode} output must be a varnode or null")
    where = f"{location} P-code {sequence} {opcode}"

    if opcode in {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN"}:
        if opcode == "RETURN":
            if output is not None:
                raise PcodeLoweringError(f"{where}: RETURN cannot have an output")
            if len(inputs) != 1:
                raise PcodeLoweringError(f"{where}: raw RETURN requires exactly one target varnode")
            return ["return 0;"], "RETURN"
        if opcode in {"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND"}:
            raise PcodeLoweringError(f"{where}: branch targets require function CFG metadata")
        raise PcodeLoweringError(f"{where}: control flow or userop is outside this lowering subset")

    if opcode in {"LOAD", "STORE"}:
        raise PcodeLoweringError(f"{where}: memory operation requires language address-space metadata")
    if output is None:
        raise PcodeLoweringError(f"{where}: expected an output varnode")
    out_size = _size(output, where + " output")

    if opcode == "COPY":
        if len(inputs) != 1:
            raise PcodeLoweringError(f"{where}: expected one input")
        if out_size == 10:
            prelude, value = _read_bytes_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
            return prelude + [_write_bytes_output(output, value, where, unique_layout)], None
        prelude, value, in_size = _read_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        if in_size != out_size:
            raise PcodeLoweringError(f"{where}: COPY input/output sizes differ")
        return prelude + [_write_output(output, value, where, unique_layout, big_endian)], None

    if opcode in _BINARY or opcode in {
        "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
        "INT_SLESS", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
        "BOOL_AND", "BOOL_OR", "BOOL_XOR",
    }:
        if len(inputs) != 2:
            raise PcodeLoweringError(f"{where}: expected two inputs")
        left_prelude, left, left_size = _read_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        right_prelude, right, right_size = _read_expr(inputs[1], f"rvi_{sequence}_a1", unique_layout, big_endian)
        if left_size != right_size:
            raise PcodeLoweringError(f"{where}: binary input sizes differ")
        if opcode.startswith("BOOL_") and (left_size != 1 or out_size != 1):
            raise PcodeLoweringError(f"{where}: boolean operations require 1-byte inputs and output")
        if opcode in {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS",
                      "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW"} and out_size != 1:
            raise PcodeLoweringError(f"{where}: comparison output must be 1 byte")
        if opcode in _BINARY and out_size != left_size:
            raise PcodeLoweringError(f"{where}: arithmetic input/output sizes differ")
        mask = f"rvi_mask({out_size})"
        expr = {
            **{name: f"(({left} {operator} {right}) & {mask})" for name, operator in _BINARY.items()},
            "INT_EQUAL": f"({left} == {right})",
            "INT_NOTEQUAL": f"({left} != {right})",
            "INT_LESS": f"(({left} & rvi_mask({left_size})) < ({right} & rvi_mask({right_size})))",
            "INT_LESSEQUAL": f"(({left} & rvi_mask({left_size})) <= ({right} & rvi_mask({right_size})))",
            "INT_SLESS": f"rvi_signed_less({left}, {right}, {left_size})",
            "INT_SLESSEQUAL": f"!rvi_signed_less({right}, {left}, {left_size})",
            "INT_CARRY": f"rvi_carry({left}, {right}, {left_size})",
            "INT_SCARRY": f"rvi_signed_carry({left}, {right}, {left_size})",
            "INT_SBORROW": f"rvi_signed_borrow({left}, {right}, {left_size})",
            "BOOL_AND": f"(({left} != 0) && ({right} != 0))",
            "BOOL_OR": f"(({left} != 0) || ({right} != 0))",
            "BOOL_XOR": f"(({left} != 0) != ({right} != 0))",
        }[opcode]
        return left_prelude + right_prelude + [_write_output(output, expr, where, unique_layout, big_endian)], None

    if opcode in {"INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"}:
        if len(inputs) != 2:
            raise PcodeLoweringError(f"{where}: expected two inputs")
        left_prelude, left, left_size = _read_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        right_prelude, right, right_size = _read_expr(inputs[1], f"rvi_{sequence}_a1", unique_layout, big_endian)
        if left_size != right_size or out_size != left_size:
            raise PcodeLoweringError(f"{where}: integer division input/output sizes differ")
        signed = opcode in {"INT_SDIV", "INT_SREM"}
        remainder = opcode in {"INT_REM", "INT_SREM"}
        prelude = left_prelude + right_prelude + [f"uint64_t rvi_{sequence}_quotient;"]
        prelude.append(
            f"if (rvi_integer_divmod({left}, {right}, {left_size}, {_c_bool(signed)}, "
            f"{_c_bool(remainder)}, &rvi_{sequence}_quotient) != 0) return -1;"
        )
        return prelude + [_write_output(output, f"rvi_{sequence}_quotient", where, unique_layout, big_endian)], None

    if opcode in {
        "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
        "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV",
    }:
        if len(inputs) != 2:
            raise PcodeLoweringError(f"{where}: expected two inputs")
        left_width = _size(inputs[0], f"rvi_{sequence}_a0")
        right_width = _size(inputs[1], f"rvi_{sequence}_a1")
        if left_width == 10 or right_width == 10:
            if not supports_binary80 or big_endian:
                raise PcodeLoweringError(f"{where}: binary80 arithmetic requires little-endian x86")
            if left_width != 10 or right_width != 10:
                raise PcodeLoweringError(f"{where}: binary80 operands must both be 10 bytes")
            left_prelude, left = _read_bytes_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
            right_prelude, right = _read_bytes_expr(inputs[1], f"rvi_{sequence}_a1", unique_layout, big_endian)
            comparison = opcode in {"FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL"}
            if comparison:
                if out_size != 1:
                    raise PcodeLoweringError(f"{where}: floating comparison output must be 1 byte")
                compare_code = {
                    "FLOAT_EQUAL": "RVI_FLOAT80_EQUAL", "FLOAT_NOTEQUAL": "RVI_FLOAT80_NOTEQUAL",
                    "FLOAT_LESS": "RVI_FLOAT80_LESS", "FLOAT_LESSEQUAL": "RVI_FLOAT80_LESSEQUAL",
                }[opcode]
                result = f"rvi_{sequence}_comparison"
                return left_prelude + right_prelude + [
                    f"int {result};",
                    f"if (rvi_float80_compare({left}, {right}, {compare_code}, &{result}) != 0) return -1;",
                    _write_output(output, result, where, unique_layout, big_endian),
                ], None
            if out_size != 10:
                raise PcodeLoweringError(f"{where}: binary80 arithmetic output must be 10 bytes")
            operation_code = {
                "FLOAT_ADD": "RVI_FLOAT80_ADD", "FLOAT_SUB": "RVI_FLOAT80_SUB",
                "FLOAT_MULT": "RVI_FLOAT80_MULT", "FLOAT_DIV": "RVI_FLOAT80_DIV",
            }[opcode]
            result = f"rvi_{sequence}_result"
            return left_prelude + right_prelude + [
                f"uint8_t {result}[10];",
                f"if (rvi_float80_binary({left}, {right}, {operation_code}, {result}) != 0) return -1;",
                _write_bytes_output(output, result, where, unique_layout),
            ], None
        left_prelude, left, left_size = _read_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        right_prelude, right, right_size = _read_expr(inputs[1], f"rvi_{sequence}_a1", unique_layout, big_endian)
        if left_size != right_size or left_size not in {4, 8}:
            raise PcodeLoweringError(f"{where}: floating inputs must both be 4 or 8 bytes")
        comparison = opcode in {"FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL"}
        if comparison:
            if out_size != 1:
                raise PcodeLoweringError(f"{where}: floating comparison output must be 1 byte")
            ctype = "float" if left_size == 4 else "double"
            to_float = "rvi_float32" if left_size == 4 else "rvi_float64"
            a = f"rvi_{sequence}_fa"
            b = f"rvi_{sequence}_fb"
            prelude = left_prelude + right_prelude + [
                f"{ctype} {a} = {to_float}({left});",
                f"{ctype} {b} = {to_float}({right});",
            ]
            expr = {
                "FLOAT_EQUAL": f"(!isnan({a}) && !isnan({b}) && {a} == {b})",
                "FLOAT_NOTEQUAL": f"(!isnan({a}) && !isnan({b}) && {a} != {b})",
                "FLOAT_LESS": f"(!isnan({a}) && !isnan({b}) && {a} < {b})",
                "FLOAT_LESSEQUAL": f"(!isnan({a}) && !isnan({b}) && {a} <= {b})",
            }[opcode]
        else:
            if out_size != left_size:
                raise PcodeLoweringError(f"{where}: floating arithmetic input/output sizes differ")
            operation_code = {
                "FLOAT_ADD": "RVI_FLOAT_ADD", "FLOAT_SUB": "RVI_FLOAT_SUB",
                "FLOAT_MULT": "RVI_FLOAT_MULT", "FLOAT_DIV": "RVI_FLOAT_DIV",
            }[opcode]
            expr = f"rvi_float_binary({left}, {right}, {left_size}, {operation_code})"
            prelude = left_prelude + right_prelude
        return prelude + [_write_output(output, expr, where, unique_layout, big_endian)], None

    if opcode in {"FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "ROUND", "FLOAT2FLOAT", "INT2FLOAT", "TRUNC", "FLOAT_NAN"}:
        if len(inputs) != 1:
            raise PcodeLoweringError(f"{where}: expected one input")
        source_size = _size(inputs[0], f"rvi_{sequence}_a0")
        if source_size == 10:
            if not supports_binary80 or big_endian:
                raise PcodeLoweringError(f"{where}: binary80 operations require little-endian x86")
            source_prelude, source = _read_bytes_expr(
                inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
            if opcode in {"FLOAT_NEG", "FLOAT_ABS"} and out_size == 10:
                result = f"rvi_{sequence}_result"
                clear_sign = "0" if opcode == "FLOAT_NEG" else "1"
                return source_prelude + [
                    f"uint8_t {result}[10];",
                    f"rvi_float80_sign({source}, {clear_sign}, {result});",
                    _write_bytes_output(output, result, where, unique_layout),
                ], None
            if opcode in {"FLOAT_SQRT", "ROUND"} and out_size == 10:
                result = f"rvi_{sequence}_result"
                op = "RVI_FLOAT80_SQRT" if opcode == "FLOAT_SQRT" else "RVI_FLOAT80_ROUND"
                return source_prelude + [
                    f"uint8_t {result}[10];",
                    f"if (rvi_float80_unary({source}, {op}, {result}) != 0) return -1;",
                    _write_bytes_output(output, result, where, unique_layout),
                ], None
            if opcode == "FLOAT2FLOAT" and out_size in {4, 8}:
                converted = f"rvi_{sequence}_converted"
                return source_prelude + [
                    f"uint64_t {converted};",
                    f"if (rvi_float80_to_float({source}, {out_size}, &{converted}) != 0) return -1;",
                    _write_output(output, converted, where, unique_layout, big_endian),
                ], None
            if opcode == "FLOAT_NAN" and out_size == 1:
                result = f"rvi_{sequence}_isnan"
                return source_prelude + [
                    f"int {result};",
                    f"if (rvi_float80_isnan({source}, &{result}) != 0) return -1;",
                    _write_output(output, result, where, unique_layout, big_endian),
                ], None
            if opcode == "TRUNC" and 1 <= out_size <= 8:
                truncated = f"rvi_{sequence}_truncated"
                return source_prelude + [
                    f"uint64_t {truncated};",
                    f"if (rvi_float80_trunc({source}, {out_size}, &{truncated}) != 0) return -1;",
                    _write_output(output, truncated, where, unique_layout, big_endian),
                ], None
            raise PcodeLoweringError(f"{where}: unsupported binary80 operation or width")
        source_prelude, source, source_size = _read_expr(
            inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        prelude = list(source_prelude)
        if opcode == "FLOAT_NAN":
            if source_size not in {4, 8} or out_size != 1:
                raise PcodeLoweringError(f"{where}: FLOAT_NAN requires a 4/8-byte input and 1-byte output")
            expr = f"isnan({('rvi_float32' if source_size == 4 else 'rvi_float64')}({source}))"
        elif opcode in {"FLOAT_NEG", "FLOAT_ABS"}:
            if source_size not in {4, 8} or source_size != out_size:
                raise PcodeLoweringError(f"{where}: floating unary input/output sizes must match at 4 or 8 bytes")
            sign = "UINT64_C(0x80000000)" if source_size == 4 else "UINT64_C(0x8000000000000000)"
            expr = f"(({source}) {'^' if opcode == 'FLOAT_NEG' else '& ~'} {sign})"
        elif opcode in {"FLOAT_SQRT", "ROUND"}:
            if source_size not in {4, 8} or source_size != out_size:
                raise PcodeLoweringError(f"{where}: floating unary input/output sizes must match at 4 or 8 bytes")
            helper = "rvi_float_sqrt" if opcode == "FLOAT_SQRT" else "rvi_float_round"
            expr = f"{helper}({source}, {source_size})"
        elif opcode == "FLOAT2FLOAT":
            if source_size not in {4, 8} or out_size not in {4, 8, 10}:
                raise PcodeLoweringError(f"{where}: FLOAT2FLOAT widths must be 4, 8, or 10 bytes")
            if source_size == out_size:
                raise PcodeLoweringError(f"{where}: FLOAT2FLOAT input/output widths must differ")
            if out_size == 10:
                if not supports_binary80 or big_endian:
                    raise PcodeLoweringError(f"{where}: binary80 operations require little-endian x86")
                result = f"rvi_{sequence}_result"
                prelude.extend([
                    f"uint8_t {result}[10];",
                    f"if (rvi_float80_from_float({source}, {source_size}, {result}) != 0) return -1;",
                ])
                return prelude + [_write_bytes_output(output, result, where, unique_layout)], None
            expr = f"rvi_float_convert({source}, {source_size}, {out_size})"
        elif opcode == "INT2FLOAT":
            if out_size not in {4, 8, 10}:
                raise PcodeLoweringError(f"{where}: INT2FLOAT output must be 4, 8, or 10 bytes")
            if out_size == 10:
                if not supports_binary80 or big_endian:
                    raise PcodeLoweringError(f"{where}: binary80 operations require little-endian x86")
                result = f"rvi_{sequence}_result"
                prelude.extend([
                    f"uint8_t {result}[10];",
                    f"if (rvi_float80_from_integer({source}, {source_size}, {result}) != 0) return -1;",
                ])
                return prelude + [_write_bytes_output(output, result, where, unique_layout)], None
            expr = f"rvi_int_to_float({source}, {source_size}, {out_size})"
        else:  # TRUNC
            if source_size not in {4, 8}:
                raise PcodeLoweringError(f"{where}: TRUNC input must be 4 or 8 bytes")
            prelude.append(f"uint64_t rvi_{sequence}_truncated;")
            prelude.append(
                f"if (rvi_float_trunc_to_int({source}, {source_size}, {out_size}, "
                f"&rvi_{sequence}_truncated) != 0) return -1;"
            )
            expr = f"rvi_{sequence}_truncated"
        return prelude + [_write_output(output, expr, where, unique_layout, big_endian)], None

    if opcode in {
        "INT_2COMP", "INT_NEGATE", "BOOL_NEGATE", "INT_ZEXT", "INT_SEXT",
        "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "POPCOUNT", "SUBPIECE",
    }:
        expected = 2 if opcode in {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "SUBPIECE"} else 1
        if len(inputs) != expected:
            raise PcodeLoweringError(f"{where}: expected {expected} inputs")
        source_prelude, source, source_size = _read_expr(inputs[0], f"rvi_{sequence}_a0", unique_layout, big_endian)
        args = list(source_prelude)
        if opcode in {"INT_2COMP", "INT_NEGATE"}:
            if source_size != out_size:
                raise PcodeLoweringError(f"{where}: unary integer input/output sizes differ")
            operator = f"~({source})" if opcode == "INT_NEGATE" else f"(UINT64_C(0) - ({source}))"
            expr = f"({operator} & rvi_mask({out_size}))"
        elif opcode == "BOOL_NEGATE":
            if source_size != 1 or out_size != 1:
                raise PcodeLoweringError(f"{where}: BOOL_NEGATE requires 1-byte input and output")
            expr = f"({source} == 0)"
        elif opcode == "INT_ZEXT":
            if source_size >= out_size:
                raise PcodeLoweringError(f"{where}: INT_ZEXT output must be wider than input")
            expr = source
        elif opcode == "INT_SEXT":
            if source_size >= out_size:
                raise PcodeLoweringError(f"{where}: INT_SEXT output must be wider than input")
            expr = f"rvi_sign_extend({source}, {source_size})"
        elif opcode == "POPCOUNT":
            expr = f"rvi_popcount({source})"
        else:
            shift_prelude, shift, _ = _read_expr(inputs[1], f"rvi_{sequence}_a1", unique_layout, big_endian)
            args += shift_prelude
            if opcode == "SUBPIECE":
                if not inputs[1].get("constant") or inputs[1].get("space") != "const":
                    raise PcodeLoweringError(f"{where}: SUBPIECE offset must be constant")
                byte_offset = _hex(inputs[1].get("offset"), where)
                expr = f"({source} >> {byte_offset * 8})" if byte_offset < 8 else "UINT64_C(0)"
            elif opcode == "INT_LEFT":
                if source_size != out_size:
                    raise PcodeLoweringError(f"{where}: shift input/output sizes differ")
                expr = f"rvi_left({source}, {shift}, {out_size})"
            elif opcode == "INT_RIGHT":
                if source_size != out_size:
                    raise PcodeLoweringError(f"{where}: shift input/output sizes differ")
                expr = f"rvi_right({source}, {shift}, {out_size})"
            else:
                if source_size != out_size:
                    raise PcodeLoweringError(f"{where}: shift input/output sizes differ")
                expr = f"rvi_signed_right({source}, {shift}, {out_size})"
        return args + [_write_output(output, expr, where, unique_layout, big_endian)], None

    raise PcodeLoweringError(f"{where}: opcode is not implemented")


_RUNTIME = r'''#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <float.h>
#include <math.h>

typedef int (*RviReadBytes)(void *, const char *, uint64_t, size_t, uint8_t *);
typedef int (*RviWriteBytes)(void *, const char *, uint64_t, size_t, const uint8_t *);
typedef int (*RviCallFunction)(void *, uint64_t);
typedef int (*RviUseropFunction)(void *, uint32_t, const uint64_t *, const unsigned *,
                                 size_t, uint64_t *, unsigned);
typedef struct {
    void *opaque;
    RviReadBytes read;
    RviWriteBytes write;
    RviCallFunction call;
    RviUseropFunction userop;
} RviPcodeContext;

static uint64_t rvi_mask(unsigned size) {
    return size == 8 ? UINT64_MAX : (UINT64_C(1) << (size * 8)) - 1;
}
static uint64_t rvi_sign_extend(uint64_t value, unsigned size) {
    uint64_t mask = rvi_mask(size), sign = UINT64_C(1) << (size * 8 - 1);
    value &= mask;
    return (value & sign) ? (value | ~mask) : value;
}
static int rvi_signed_less(uint64_t left, uint64_t right, unsigned size) {
    uint64_t mask = rvi_mask(size), sign = UINT64_C(1) << (size * 8 - 1);
    left &= mask; right &= mask;
    if ((left & sign) != (right & sign)) return (left & sign) != 0;
    return left < right;
}
static int rvi_carry(uint64_t left, uint64_t right, unsigned size) {
    uint64_t mask = rvi_mask(size);
    left &= mask; right &= mask;
    return left > mask - right;
}
static int rvi_signed_carry(uint64_t left, uint64_t right, unsigned size) {
    uint64_t mask = rvi_mask(size), sign = UINT64_C(1) << (size * 8 - 1);
    uint64_t result = (left + right) & mask;
    return ((~(left ^ right) & (left ^ result) & sign) != 0);
}
static int rvi_signed_borrow(uint64_t left, uint64_t right, unsigned size) {
    uint64_t mask = rvi_mask(size), sign = UINT64_C(1) << (size * 8 - 1);
    uint64_t result = (left - right) & mask;
    return (((left ^ right) & (left ^ result) & sign) != 0);
}
static uint64_t rvi_left(uint64_t value, uint64_t shift, unsigned size) {
    unsigned bits = size * 8;
    return shift >= bits ? 0 : (value << shift) & rvi_mask(size);
}
static uint64_t rvi_right(uint64_t value, uint64_t shift, unsigned size) {
    unsigned bits = size * 8;
    return shift >= bits ? 0 : (value & rvi_mask(size)) >> shift;
}
static uint64_t rvi_signed_right(uint64_t value, uint64_t shift, unsigned size) {
    unsigned bits = size * 8;
    uint64_t mask = rvi_mask(size), sign = UINT64_C(1) << (bits - 1);
    value &= mask;
    if (shift >= bits) return (value & sign) ? mask : 0;
    if (shift == 0) return value;
    return (value >> shift) | ((value & sign) ? (mask ^ (mask >> shift)) : 0);
}
static uint64_t rvi_popcount(uint64_t value) {
    uint64_t count = 0;
    while (value) { count += value & 1; value >>= 1; }
    return count;
}
enum { RVI_FLOAT_ADD = 1, RVI_FLOAT_SUB = 2, RVI_FLOAT_MULT = 3, RVI_FLOAT_DIV = 4 };
enum {
    RVI_FLOAT80_ADD = 1, RVI_FLOAT80_SUB = 2, RVI_FLOAT80_MULT = 3, RVI_FLOAT80_DIV = 4,
    RVI_FLOAT80_EQUAL = 5, RVI_FLOAT80_NOTEQUAL = 6,
    RVI_FLOAT80_LESS = 7, RVI_FLOAT80_LESSEQUAL = 8,
    RVI_FLOAT80_SQRT = 9, RVI_FLOAT80_ROUND = 10
};
static float rvi_float32(uint64_t bits) {
    uint32_t word = (uint32_t)bits;
    float value;
    memcpy(&value, &word, sizeof(value));
    return value;
}
static double rvi_float64(uint64_t bits) {
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}
static uint64_t rvi_float32_bits(float value) {
    uint32_t word;
    memcpy(&word, &value, sizeof(word));
    return word;
}
static uint64_t rvi_float64_bits(double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}
static uint64_t rvi_float_binary(uint64_t left, uint64_t right, unsigned size, unsigned op) {
    if (size == 4) {
        float a = rvi_float32(left), b = rvi_float32(right);
        volatile float result;
        switch (op) {
        case RVI_FLOAT_ADD: result = a + b; break;
        case RVI_FLOAT_SUB: result = a - b; break;
        case RVI_FLOAT_MULT: result = a * b; break;
        case RVI_FLOAT_DIV: result = a / b; break;
        default: return 0;
        }
        if (isfinite(a) && isfinite(b) && isinf(result) && !(op == RVI_FLOAT_DIV && b == 0.0f))
            result = NAN;
        return rvi_float32_bits(result);
    }
    if (size == 8) {
        double a = rvi_float64(left), b = rvi_float64(right);
        volatile double result;
        switch (op) {
        case RVI_FLOAT_ADD: result = a + b; break;
        case RVI_FLOAT_SUB: result = a - b; break;
        case RVI_FLOAT_MULT: result = a * b; break;
        case RVI_FLOAT_DIV: result = a / b; break;
        default: return 0;
        }
        if (isfinite(a) && isfinite(b) && isinf(result) && !(op == RVI_FLOAT_DIV && b == 0.0))
            result = NAN;
        return rvi_float64_bits(result);
    }
    return 0;
}
static uint64_t rvi_float_sqrt(uint64_t bits, unsigned size) {
    if (size == 4) return rvi_float32_bits(sqrtf(rvi_float32(bits)));
    if (size == 8) return rvi_float64_bits(sqrt(rvi_float64(bits)));
    return 0;
}
static uint64_t rvi_float_round(uint64_t bits, unsigned size) {
    if (size == 4) return rvi_float32_bits(roundf(rvi_float32(bits)));
    if (size == 8) return rvi_float64_bits(round(rvi_float64(bits)));
    return 0;
}
static uint64_t rvi_float_convert(uint64_t bits, unsigned input_size, unsigned output_size) {
    if (input_size == 4 && output_size == 8)
        return rvi_float64_bits((double)rvi_float32(bits));
    if (input_size == 8 && output_size == 4)
        return rvi_float32_bits((float)rvi_float64(bits));
    return 0;
}
static int64_t rvi_signed_integer(uint64_t value, unsigned size) {
    uint64_t extended = rvi_sign_extend(value, size);
    int64_t result;
    memcpy(&result, &extended, sizeof(result));
    return result;
}
static int rvi_float80_host_supported(void) {
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
    return LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384 && sizeof(long double) >= 10;
#else
    return 0;
#endif
}
static int rvi_float80_load(const uint8_t input[10], long double *value) {
    uint8_t bytes[sizeof(long double)] = {0};
    if (!input || !value || !rvi_float80_host_supported()) return -1;
    memcpy(bytes, input, 10);
    memcpy(value, bytes, sizeof(*value));
    return 0;
}
static int rvi_float80_store(long double value, uint8_t output[10]) {
    uint8_t bytes[sizeof(long double)] = {0};
    if (!output || !rvi_float80_host_supported()) return -1;
    memcpy(bytes, &value, sizeof(value));
    memcpy(output, bytes, 10);
    return 0;
}
static int rvi_float80_from_float(uint64_t bits, unsigned size, uint8_t output[10]) {
    long double value;
    if (!rvi_float80_host_supported()) return -1;
    if (size == 4) value = (long double)rvi_float32(bits);
    else if (size == 8) value = (long double)rvi_float64(bits);
    else return -1;
    return rvi_float80_store(value, output);
}
static int rvi_float80_to_float(const uint8_t input[10], unsigned size, uint64_t *bits) {
    long double value;
    if (!bits || rvi_float80_load(input, &value) != 0) return -1;
    if (size == 4) *bits = rvi_float32_bits((float)value);
    else if (size == 8) *bits = rvi_float64_bits((double)value);
    else return -1;
    return 0;
}
static int rvi_float80_from_integer(uint64_t value, unsigned size, uint8_t output[10]) {
    if (!rvi_float80_host_supported() || size == 0 || size > 8) return -1;
    return rvi_float80_store((long double)rvi_signed_integer(value, size), output);
}
static int rvi_float80_binary(const uint8_t left[10], const uint8_t right[10],
                              unsigned op, uint8_t output[10]) {
    long double a, b, result;
    volatile long double rounded;
    if (rvi_float80_load(left, &a) != 0 || rvi_float80_load(right, &b) != 0) return -1;
    switch (op) {
    case RVI_FLOAT80_ADD: rounded = a + b; break;
    case RVI_FLOAT80_SUB: rounded = a - b; break;
    case RVI_FLOAT80_MULT: rounded = a * b; break;
    case RVI_FLOAT80_DIV: rounded = a / b; break;
    default: return -1;
    }
    result = rounded;
    if (isfinite(a) && isfinite(b) && isinf(result) &&
        !(op == RVI_FLOAT80_DIV && b == 0.0L)) result = nanl("");
    return rvi_float80_store(result, output);
}
static int rvi_float80_compare(const uint8_t left[10], const uint8_t right[10],
                               unsigned op, int *result) {
    long double a, b;
    if (!result || rvi_float80_load(left, &a) != 0 || rvi_float80_load(right, &b) != 0) return -1;
    *result = 0;
    if (isnan(a) || isnan(b)) return 0;
    switch (op) {
    case RVI_FLOAT80_EQUAL: *result = a == b; break;
    case RVI_FLOAT80_NOTEQUAL: *result = a != b; break;
    case RVI_FLOAT80_LESS: *result = a < b; break;
    case RVI_FLOAT80_LESSEQUAL: *result = a <= b; break;
    default: return -1;
    }
    return 0;
}
static void rvi_float80_sign(const uint8_t input[10], int clear_sign, uint8_t output[10]) {
    memcpy(output, input, 10);
    if (clear_sign) output[9] &= 0x7f;
    else output[9] ^= 0x80;
}
static int rvi_float80_unary(const uint8_t input[10], unsigned op, uint8_t output[10]) {
    long double value;
    if (rvi_float80_load(input, &value) != 0) return -1;
    if (op == RVI_FLOAT80_SQRT) value = sqrtl(value);
    else if (op == RVI_FLOAT80_ROUND) value = roundl(value);
    else return -1;
    return rvi_float80_store(value, output);
}
static int rvi_float80_isnan(const uint8_t input[10], int *result) {
    long double value;
    if (!result || rvi_float80_load(input, &value) != 0) return -1;
    *result = isnan(value);
    return 0;
}
static int rvi_float80_trunc(const uint8_t input[10], unsigned size, uint64_t *result) {
    long double value, truncated, limit;
    if (!result || size == 0 || size > 8 || rvi_float80_load(input, &value) != 0) return -1;
    truncated = truncl(value);
    limit = ldexpl(1.0L, size * 8 - 1);
    if (!isfinite(truncated) || truncated < -limit || truncated >= limit) return -1;
    *result = (uint64_t)(int64_t)truncated & rvi_mask(size);
    return 0;
}
static uint64_t rvi_int_to_float(uint64_t value, unsigned input_size, unsigned output_size) {
    int64_t signed_value = rvi_signed_integer(value, input_size);
    if (output_size == 4) return rvi_float32_bits((float)signed_value);
    if (output_size == 8) return rvi_float64_bits((double)signed_value);
    return 0;
}
static int rvi_integer_divmod(uint64_t left, uint64_t right, unsigned size,
                              int is_signed, int remainder, uint64_t *result) {
    uint64_t mask = rvi_mask(size);
    left &= mask;
    right &= mask;
    if (!result || right == 0) return -1;
    if (!is_signed) {
        *result = (remainder ? left % right : left / right) & mask;
        return 0;
    }
    int64_t a = rvi_signed_integer(left, size);
    int64_t b = rvi_signed_integer(right, size);
    int64_t minimum = size == 8 ? INT64_MIN : -(INT64_C(1) << (size * 8 - 1));
    if (a == minimum && b == -1) return -1;
    int64_t quotient = remainder ? a % b : a / b;
    *result = (uint64_t)quotient & mask;
    return 0;
}
static int rvi_float_trunc_to_int(uint64_t bits, unsigned input_size,
                                  unsigned output_size, uint64_t *result) {
    if (!result || (input_size != 4 && input_size != 8) || output_size == 0 || output_size > 8)
        return -1;
    double value = input_size == 4 ? (double)rvi_float32(bits) : rvi_float64(bits);
    double truncated = trunc(value);
    double limit = ldexp(1.0, output_size * 8 - 1);
    if (!isfinite(truncated) || truncated < -limit || truncated >= limit) return -1;
    int64_t signed_value = (int64_t)truncated;
    *result = (uint64_t)signed_value & rvi_mask(output_size);
    return 0;
}
static int rvi_read_bytes(RviPcodeContext *ctx, uint8_t *unique, uint64_t unique_base,
                          size_t unique_size, const char *space, uint64_t offset,
                          unsigned size, uint8_t *bytes) {
    if (size == 0 || size > 10) return -1;
    if (strcmp(space, "unique") == 0) {
        if (offset < unique_base || offset - unique_base > unique_size ||
            size > unique_size - (size_t)(offset - unique_base)) return -1;
        memcpy(bytes, unique + (size_t)(offset - unique_base), size);
        return 0;
    }
    return ctx && ctx->read ? ctx->read(ctx->opaque, space, offset, size, bytes) : -1;
}
static int rvi_write_bytes(RviPcodeContext *ctx, uint8_t *unique, uint64_t unique_base,
                           size_t unique_size, const char *space, uint64_t offset,
                           unsigned size, const uint8_t *bytes) {
    if (size == 0 || size > 10) return -1;
    if (strcmp(space, "unique") == 0) {
        if (offset < unique_base || offset - unique_base > unique_size ||
            size > unique_size - (size_t)(offset - unique_base)) return -1;
        memcpy(unique + (size_t)(offset - unique_base), bytes, size);
        return 0;
    }
    return ctx && ctx->write ? ctx->write(ctx->opaque, space, offset, size, bytes) : -1;
}
static int rvi_read_value(RviPcodeContext *ctx, uint8_t *unique, uint64_t unique_base,
                          size_t unique_size, const char *space, uint64_t offset,
                          unsigned size, int big_endian, uint64_t *value) {
    uint8_t bytes[8] = {0};
    if (size == 0 || size > 8) return -1;
    if (rvi_read_bytes(ctx, unique, unique_base, unique_size, space, offset,
                       size, bytes) != 0) return -1;
    *value = 0;
    for (unsigned i = 0; i < size; i++) {
        unsigned index = big_endian ? i : size - 1 - i;
        *value = (*value << 8) | bytes[index];
    }
    return 0;
}
static int rvi_write_value(RviPcodeContext *ctx, uint8_t *unique, uint64_t unique_base,
                           size_t unique_size, const char *space, uint64_t offset,
                           unsigned size, int big_endian, uint64_t value) {
    uint8_t bytes[8] = {0};
    if (size == 0 || size > 8) return -1;
    value &= rvi_mask(size);
    for (unsigned i = 0; i < size; i++) {
        unsigned shift = big_endian ? (size - 1 - i) * 8 : i * 8;
        bytes[i] = (uint8_t)(value >> shift);
    }
    return rvi_write_bytes(ctx, unique, unique_base, unique_size, space, offset, size, bytes);
}
static int rvi_read_space(RviPcodeContext *ctx, const char *space, uint64_t offset,
                          unsigned size, int big_endian, uint64_t *value) {
    uint8_t bytes[8] = {0};
    if (!ctx || !ctx->read || size == 0 || size > 8 ||
        ctx->read(ctx->opaque, space, offset, size, bytes) != 0) return -1;
    *value = 0;
    for (unsigned i = 0; i < size; i++) {
        unsigned index = big_endian ? i : size - 1 - i;
        *value = (*value << 8) | bytes[index];
    }
    return 0;
}
static int rvi_write_space(RviPcodeContext *ctx, const char *space, uint64_t offset,
                           unsigned size, int big_endian, uint64_t value) {
    uint8_t bytes[8] = {0};
    if (!ctx || !ctx->write || size == 0 || size > 8) return -1;
    value &= rvi_mask(size);
    for (unsigned i = 0; i < size; i++) {
        unsigned shift = big_endian ? (size - 1 - i) * 8 : i * 8;
        bytes[i] = (uint8_t)(value >> shift);
    }
    return ctx->write(ctx->opaque, space, offset, size, bytes);
}
static int rvi_call(RviPcodeContext *ctx, uint64_t target) {
    return ctx && ctx->call ? ctx->call(ctx->opaque, target) : -1;
}
'''


def compile_function(
    function_row: dict, address_spaces: dict, *, include_runtime: bool = True,
) -> tuple[str, int]:
    """Compile scalar raw P-code with direct intra-function branches; reject gaps."""
    if function_row.get("format") != CORPUS_FORMAT or function_row.get("found") is not True:
        raise PcodeLoweringError("input row must be a found GhidraFunctionInstructions/1 function")
    function = function_row.get("function")
    instructions = function_row.get("instructions")
    if not isinstance(function, dict) or not isinstance(instructions, list):
        raise PcodeLoweringError("function metadata or instructions are missing")
    if type(function_row.get("instruction_count")) is not int or function_row["instruction_count"] != len(instructions):
        raise PcodeLoweringError("instruction_count does not match the instruction list")
    function_address = function.get("address")
    if not isinstance(function_address, str) or not function_address:
        raise PcodeLoweringError("function address is missing")
    if address_spaces.get("format") != SPACES_FORMAT:
        raise PcodeLoweringError(f"expected {SPACES_FORMAT} address-space table")
    language_id = address_spaces.get("language_id")
    if not isinstance(language_id, str) or not language_id:
        raise PcodeLoweringError("address-space table language_id is missing")
    supports_binary80 = language_id.split(":", 1)[0].lower() == "x86"
    default_space = address_spaces.get("default_space")
    if not isinstance(default_space, str) or not default_space:
        raise PcodeLoweringError("address-space table default_space is missing")
    big_endian = address_spaces.get("big_endian")
    if not isinstance(big_endian, bool):
        raise PcodeLoweringError("address-space table big_endian must be a boolean")

    unique_offsets: list[tuple[int, int]] = []
    instruction_addresses: list[int] = []
    for instruction_index, instruction in enumerate(instructions):
        if not isinstance(instruction, dict) or not isinstance(instruction.get("pcode"), list):
            raise PcodeLoweringError(f"instruction {instruction_index}: expected P-code list")
        address = _hex(instruction.get("address"), f"instruction {instruction_index} address")
        if address in instruction_addresses:
            raise PcodeLoweringError(f"instruction {instruction_index}: duplicate address 0x{address:x}")
        instruction_addresses.append(address)
        for operation in instruction["pcode"]:
            if not isinstance(operation, dict):
                raise PcodeLoweringError(f"instruction {instruction_index}: malformed P-code operation")
            inputs = operation.get("inputs")
            if not isinstance(inputs, list) or any(not isinstance(node, dict) for node in inputs):
                raise PcodeLoweringError(f"instruction {instruction_index}: malformed P-code inputs")
            for node in [operation.get("output"), *inputs]:
                if isinstance(node, dict) and node.get("space") == "unique" and node.get("constant") is False:
                    offset = _hex(node.get("offset"), f"instruction {instruction_index} unique varnode")
                    size = _size(node, f"instruction {instruction_index} unique varnode")
                    unique_offsets.append((offset, size))

    merged_unique_ranges: list[list[int]] = []
    for offset, size in sorted(unique_offsets):
        end = offset + size
        if merged_unique_ranges and offset <= merged_unique_ranges[-1][1]:
            merged_unique_ranges[-1][1] = max(merged_unique_ranges[-1][1], end)
        else:
            merged_unique_ranges.append([offset, end])
    unique_layout: list[tuple[int, int, int]] = []
    unique_size = 0
    for source_start, source_end in merged_unique_ranges:
        unique_layout.append((source_start, source_end, unique_size))
        unique_size += source_end - source_start
    if unique_size > MAX_UNIQUE_BYTES:
        raise PcodeLoweringError(f"function unique-space allocation {unique_size} exceeds {MAX_UNIQUE_BYTES} bytes")

    body: list[str] = []
    operation_count = 0
    address_table = address_spaces.get("address_spaces")
    if not isinstance(address_table, list):
        raise PcodeLoweringError("address-space table has no address_spaces list")
    spaces_by_id: dict[int, dict] = {}
    for space in address_table:
        if not isinstance(space, dict):
            raise PcodeLoweringError("address-space entry must be an object")
        space_id = _hex(space.get("space_id"), "address-space table")
        if space_id in spaces_by_id:
            raise PcodeLoweringError(f"duplicate address-space ID 0x{space_id:x}")
        spaces_by_id[space_id] = space

    labels_by_address = {address: f"rvi_label_{address:016x}" for address in instruction_addresses}
    for instruction_index, instruction in enumerate(instructions):
        address = instruction.get("address", f"instruction {instruction_index}")
        address_value = instruction_addresses[instruction_index]
        body.append(f"{labels_by_address[address_value]}: ;")
        flow_type = instruction.get("flow_type")
        flows = instruction.get("flows")
        operations = instruction["pcode"]
        if not isinstance(flows, list) or any(not isinstance(target, str) for target in flows):
            raise PcodeLoweringError(f"{address}: machine flow targets must be address strings")
        if flow_type not in {
            "FALL_THROUGH", "CONDITIONAL_JUMP", "UNCONDITIONAL_JUMP", "TERMINATOR",
            "UNCONDITIONAL_CALL", "COMPUTED_CALL", "CALL_TERMINATOR",
            "COMPUTED_JUMP", "COMPUTED_CALL_TERMINATOR",
        }:
            raise PcodeLoweringError(f"{address}: machine flow type {flow_type!r} is not supported")
        if not operations:
            if instruction.get("mnemonic", "").upper() == "NOP" and flow_type == "FALL_THROUGH":
                continue
            raise PcodeLoweringError(f"{address}: no P-code for non-NOP instruction")

        repeat_loop = False
        fallthrough_branch = False
        relative_branch_indices: set[int] = set()
        relative_targets: set[int] = set()
        for op_index, operation in enumerate(operations):
            if operation.get("opcode") not in {"BRANCH", "CBRANCH"}:
                continue
            inputs = operation.get("inputs")
            if isinstance(inputs, list) and inputs and isinstance(inputs[0], dict) and inputs[0].get("space") == "const":
                relative_branch_indices.add(op_index)
                relative_targets.add(_pcode_relative_target(
                    inputs[0], op_index, f"{address} P-code {op_index} relative target", len(operations)))
        relative_labels = {
            target: f"rvi_pcode_{address_value:016x}_{target}" for target in relative_targets
        }
        for op_index, operation in enumerate(operations):
            if op_index in relative_labels:
                body.append(f"    {relative_labels[op_index]}: ;")
            opcode = operation.get("opcode", "")
            if opcode == "CALLOTHER":
                inputs = operation.get("inputs")
                if not isinstance(inputs, list) or not inputs:
                    raise PcodeLoweringError(f"{address}: CALLOTHER lacks its userop index")
                index_node = inputs[0]
                if (not isinstance(index_node, dict) or index_node.get("space") != "const" or
                        index_node.get("constant") is not True):
                    raise PcodeLoweringError(f"{address}: CALLOTHER userop index must be constant")
                userop_index = _hex(index_node.get("offset"), f"{address} CALLOTHER userop index")
                if userop_index > 0xFFFFFFFF:
                    raise PcodeLoweringError(f"{address}: CALLOTHER userop index exceeds uint32")
                output = operation.get("output")
                if output is not None and not isinstance(output, dict):
                    raise PcodeLoweringError(f"{address}: CALLOTHER output must be a varnode or null")
                output_size = _size(output, f"{address} CALLOTHER output") if isinstance(output, dict) else 0
                argument_nodes = inputs[1:]
                if len(argument_nodes) > 256:
                    raise PcodeLoweringError(f"{address}: CALLOTHER has too many arguments")
                array_size = max(len(argument_nodes), 1)
                userop_lines = [
                    f"uint64_t rvi_{operation_count}_args[{array_size}] = {{0}};",
                    f"unsigned rvi_{operation_count}_sizes[{array_size}] = {{0}};",
                ]
                for argument_index, argument in enumerate(argument_nodes):
                    if not isinstance(argument, dict):
                        raise PcodeLoweringError(f"{address}: malformed CALLOTHER argument")
                    prelude, value, value_size = _read_expr(
                        argument, f"rvi_{operation_count}_arg{argument_index}", unique_layout, big_endian)
                    userop_lines.extend(prelude)
                    userop_lines.append(f"rvi_{operation_count}_args[{argument_index}] = {value};")
                    userop_lines.append(f"rvi_{operation_count}_sizes[{argument_index}] = {value_size};")
                userop_lines.append(f"uint64_t rvi_{operation_count}_result = 0;")
                userop_lines.append(
                    f"if (!ctx || !ctx->userop || ctx->userop(ctx->opaque, UINT32_C({userop_index}), "
                    f"rvi_{operation_count}_args, rvi_{operation_count}_sizes, {len(argument_nodes)}, "
                    f"{'&rvi_' + str(operation_count) + '_result' if output_size else 'NULL'}, {output_size}) != 0) return -1;"
                )
                if output_size:
                    userop_lines.append(_write_output(
                        output, f"rvi_{operation_count}_result", f"{address} CALLOTHER output",
                        unique_layout, big_endian))
                body.extend("    " + line for line in ["{"] + userop_lines + ["}"])
                operation_count += 1
                continue
            if opcode in {"BRANCH", "CBRANCH"}:
                inputs = operation.get("inputs")
                expected_inputs = 1 if opcode == "BRANCH" else 2
                if operation.get("output") is not None or not isinstance(inputs, list) or len(inputs) != expected_inputs:
                    raise PcodeLoweringError(f"{address}: malformed {opcode}")
                relative_branch = op_index in relative_branch_indices
                if opcode == "BRANCH" and not relative_branch and op_index != len(operations) - 1:
                    raise PcodeLoweringError(f"{address}: {opcode} must end its instruction")
                tail_call = opcode == "BRANCH" and not relative_branch and flow_type == "CALL_TERMINATOR"
                if tail_call:
                    target_address = _direct_control_target(inputs[0], default_space, f"{address} tail-call target")
                    flow_addresses = {_hex(item, f"{address} machine flow target") for item in flows}
                    if flow_addresses and target_address not in flow_addresses:
                        raise PcodeLoweringError(f"{address}: tail-call target disagrees with machine flow metadata")
                    body.append(f"    if (rvi_call(ctx, UINT64_C(0x{target_address:x})) != 0) return -1;")
                    body.append("    return 0;")
                    operation_count += 1
                    continue
                if relative_branch:
                    target_index = _pcode_relative_target(
                        inputs[0], op_index, f"{address} {opcode} relative target", len(operations))
                    target_label = relative_labels[target_index]
                else:
                    target_address = _direct_control_target(inputs[0], default_space, f"{address} {opcode} target")
                    target_label = labels_by_address.get(target_address)
                if relative_branch:
                    pass
                elif opcode == "CBRANCH" and flow_type == "FALL_THROUGH":
                    fallthrough = instruction.get("fallthrough")
                    if not isinstance(fallthrough, str) or target_address not in {
                        address_value, _hex(fallthrough, f"{address} fallthrough"),
                    }:
                        raise PcodeLoweringError(f"{address}: CBRANCH conflicts with machine fallthrough")
                    fallthrough_branch = True
                elif opcode == "BRANCH" and flow_type == "FALL_THROUGH":
                    if target_address != address_value or not fallthrough_branch:
                        raise PcodeLoweringError(f"{address}: fall-through BRANCH is not a repeat-instruction loop")
                    repeat_loop = True
                else:
                    expected_flow = "UNCONDITIONAL_JUMP" if opcode == "BRANCH" else "CONDITIONAL_JUMP"
                    if flow_type != expected_flow:
                        raise PcodeLoweringError(f"{address}: {opcode} conflicts with machine flow type {flow_type!r}")
                if not relative_branch:
                    flow_addresses = {_hex(item, f"{address} machine flow target") for item in flows}
                    if flow_addresses and target_address not in flow_addresses:
                        raise PcodeLoweringError(f"{address}: {opcode} target disagrees with machine flow metadata")
                if opcode == "BRANCH":
                    if target_label is not None:
                        branch_lines = [f"goto {target_label};"]
                    else:
                        branch_lines = [
                            f"if (rvi_call(ctx, UINT64_C(0x{target_address:x})) != 0) return -1;",
                            "return 0;",
                        ]
                else:
                    condition_prelude, condition, condition_size = _read_expr(
                        inputs[1], f"rvi_{operation_count}_condition", unique_layout, big_endian)
                    if condition_size != 1:
                        raise PcodeLoweringError(f"{address}: CBRANCH condition must be 1 byte")
                    taken = (
                        f"goto {target_label};" if target_label is not None else
                        f"if (rvi_call(ctx, UINT64_C(0x{target_address:x})) != 0) return -1; return 0;"
                    )
                    branch_lines = condition_prelude + [f"if ({condition} != 0) {{ {taken} }}"]
                body.extend("    " + line for line in ["{"] + branch_lines + ["}"])
                operation_count += 1
                continue
            if opcode == "BRANCHIND":
                inputs = operation.get("inputs")
                if operation.get("output") is not None or not isinstance(inputs, list) or len(inputs) != 1:
                    raise PcodeLoweringError(f"{address}: malformed BRANCHIND")
                if op_index != len(operations) - 1 or flow_type not in {"COMPUTED_JUMP", "COMPUTED_CALL_TERMINATOR"}:
                    raise PcodeLoweringError(f"{address}: BRANCHIND conflicts with machine flow type {flow_type!r}")
                target_prelude, target_expr, _ = _read_expr(
                    inputs[0], f"rvi_{operation_count}_branch_target", unique_layout, big_endian)
                if flow_type == "COMPUTED_CALL_TERMINATOR":
                    body.extend("    " + line for line in ["{"] + target_prelude + [
                        f"if (rvi_call(ctx, {target_expr}) != 0) return -1;", "return 0;", "}"])
                else:
                    flow_addresses = sorted({_hex(item, f"{address} computed flow target") for item in flows})
                    if not flow_addresses:
                        flow_addresses = sorted(labels_by_address)
                    switch_lines = [f"switch ({target_expr}) {{"]
                    for target in flow_addresses:
                        target_label = labels_by_address.get(target)
                        if target_label is not None:
                            switch_lines.append(f"case UINT64_C(0x{target:x}): goto {target_label};")
                        else:
                            switch_lines.append(
                                f"case UINT64_C(0x{target:x}): "
                                f"if (rvi_call(ctx, UINT64_C(0x{target:x})) != 0) return -1; return 0;")
                    switch_lines.extend(["default: return -1;", "}"])
                    body.extend("    " + line for line in ["{"] + target_prelude + switch_lines + ["}"])
                operation_count += 1
                continue
            if opcode in {"CALL", "CALLIND"}:
                inputs = operation.get("inputs")
                if operation.get("output") is not None or not isinstance(inputs, list) or len(inputs) != 1:
                    raise PcodeLoweringError(f"{address}: malformed {opcode}")
                tail_call = flow_type == "CALL_TERMINATOR" and opcode == "CALL"
                expected_flow = "UNCONDITIONAL_CALL" if opcode == "CALL" else "COMPUTED_CALL"
                if flow_type == "COMPUTED_CALL_TERMINATOR" and opcode == "CALLIND":
                    expected_flow = flow_type
                if op_index != len(operations) - 1 or flow_type != expected_flow:
                    if not tail_call or op_index != len(operations) - 1:
                        raise PcodeLoweringError(f"{address}: {opcode} conflicts with machine flow type {flow_type!r}")
                if opcode == "CALL":
                    target_address = _direct_control_target(inputs[0], default_space, f"{address} CALL target")
                    flow_addresses = {_hex(item, f"{address} machine flow target") for item in flows}
                    if flow_addresses and target_address not in flow_addresses:
                        raise PcodeLoweringError(f"{address}: CALL target disagrees with machine flow metadata")
                    call_lines = [f"if (rvi_call(ctx, UINT64_C(0x{target_address:x})) != 0) return -1;"]
                else:
                    target_prelude, target_expr, _ = _read_expr(
                        inputs[0], f"rvi_{operation_count}_call_target", unique_layout, big_endian)
                    call_lines = target_prelude + [f"if (rvi_call(ctx, {target_expr}) != 0) return -1;"]
                if tail_call or flow_type == "COMPUTED_CALL_TERMINATOR":
                    call_lines.append("return 0;")
                body.extend("    " + line for line in ["{"] + call_lines + ["}"])
                operation_count += 1
                continue
            if opcode in {"LOAD", "STORE"}:
                inputs = operation.get("inputs")
                if not isinstance(inputs, list) or not inputs or not isinstance(inputs[0], dict):
                    raise PcodeLoweringError(f"{address}: {opcode} lacks address-space ID")
                space_node = inputs[0]
                if space_node.get("space") != "const" or space_node.get("constant") is not True:
                    raise PcodeLoweringError(f"{address}: {opcode} address-space ID must be constant")
                space_id = _hex(space_node.get("offset"), f"{address} {opcode} address-space ID")
                space = spaces_by_id.get(space_id)
                if space is None:
                    raise PcodeLoweringError(f"{address}: unknown {opcode} address-space ID 0x{space_id:x}")
                unit = space.get("addressable_unit_size")
                pointer_size = space.get("pointer_size")
                name = space.get("name")
                if type(unit) is not int or unit < 1 or type(pointer_size) is not int or not 1 <= pointer_size <= 8:
                    raise PcodeLoweringError(f"{address}: invalid memory-space width metadata")
                if not isinstance(name, str) or not name:
                    raise PcodeLoweringError(f"{address}: memory-space name is missing")
                if space.get("memory") is not True:
                    raise PcodeLoweringError(f"{address}: {opcode} space is not a memory space")
                if opcode == "LOAD":
                    output = operation.get("output")
                    if not isinstance(output, dict) or len(inputs) != 2:
                        raise PcodeLoweringError(f"{address}: malformed LOAD")
                    out_size = _size(output, f"{address} LOAD output")
                    prelude, pointer, pointer_width = _read_expr(
                        inputs[1], f"rvi_{operation_count}_ptr", unique_layout, big_endian)
                    if pointer_width != pointer_size:
                        raise PcodeLoweringError(f"{address}: LOAD pointer size differs from address space")
                    if out_size == 10:
                        loaded = f"rvi_{operation_count}_loaded"
                        body.extend("    " + line for line in ["{"] + prelude)
                        body.extend([
                            f"      uint64_t rvi_{operation_count}_address = "
                            f"({pointer} * UINT64_C({unit})) & rvi_mask({pointer_size});",
                            f"      uint8_t {loaded}[10];",
                            f"      if (rvi_read_bytes(ctx, _unique, UINT64_C(0), _unique_size, "
                            f"{_escape_c_string(name)}, rvi_{operation_count}_address, 10, {loaded}) != 0) return -1;",
                            "    " + _write_bytes_output(output, loaded, f"{address} LOAD", unique_layout),
                            "    }",
                        ])
                        operation_count += 1
                        continue
                    body.extend("    " + line for line in ["{"] + prelude)
                    body.append(
                        f"      uint64_t rvi_{operation_count}_loaded;"
                    )
                    body.append(
                        f"      uint64_t rvi_{operation_count}_address = "
                        f"({pointer} * UINT64_C({unit})) & rvi_mask({pointer_size});"
                    )
                    body.append(
                        f"      if (rvi_read_space(ctx, {_escape_c_string(name)}, "
                        f"rvi_{operation_count}_address, {out_size}, {_c_bool(big_endian)}, "
                        f"&rvi_{operation_count}_loaded) != 0) return -1;"
                    )
                    body.append("    " + _write_output(
                        output, f"rvi_{operation_count}_loaded", f"{address} LOAD", unique_layout, big_endian))
                    body.append("    }")
                    operation_count += 1
                    continue
                if opcode == "STORE":
                    if operation.get("output") is not None or len(inputs) != 3:
                        raise PcodeLoweringError(f"{address}: malformed STORE")
                    pointer_prelude, pointer, pointer_size = _read_expr(
                        inputs[1], f"rvi_{operation_count}_ptr", unique_layout, big_endian)
                    if _size(inputs[2], f"{address} STORE value") == 10:
                        value_prelude, value = _read_bytes_expr(
                            inputs[2], f"rvi_{operation_count}_value", unique_layout, big_endian)
                        if pointer_size != space.get("pointer_size"):
                            raise PcodeLoweringError(f"{address}: STORE pointer size differs from address space")
                        body.extend("    " + line for line in ["{"] + pointer_prelude + value_prelude)
                        body.extend([
                            f"      uint64_t rvi_{operation_count}_address = "
                            f"({pointer} * UINT64_C({unit})) & rvi_mask({pointer_size});",
                            f"      if (rvi_write_bytes(ctx, _unique, UINT64_C(0), _unique_size, "
                            f"{_escape_c_string(name)}, rvi_{operation_count}_address, 10, {value}) != 0) return -1;",
                            "    }",
                        ])
                        operation_count += 1
                        continue
                    value_prelude, value, value_size = _read_expr(
                        inputs[2], f"rvi_{operation_count}_value", unique_layout, big_endian)
                    if pointer_size != space.get("pointer_size"):
                        raise PcodeLoweringError(f"{address}: STORE pointer size differs from address space")
                    body.extend("    " + line for line in ["{"] + pointer_prelude + value_prelude)
                    body.append(
                        f"      uint64_t rvi_{operation_count}_address = "
                        f"({pointer} * UINT64_C({unit})) & rvi_mask({pointer_size});"
                    )
                    body.append(
                        f"      if (rvi_write_space(ctx, {_escape_c_string(name)}, "
                        f"rvi_{operation_count}_address, {value_size}, {_c_bool(big_endian)}, {value}) != 0) return -1;"
                    )
                    body.append("    }")
                    operation_count += 1
                    continue

            lines, terminator = _lower_operation(
                operation, str(address), operation_count, unique_layout, big_endian, supports_binary80)
            body.extend("    " + line for line in ["{"] + lines + ["}"])
            operation_count += 1
            if terminator == "RETURN":
                if op_index != len(operations) - 1 or flow_type != "TERMINATOR":
                    raise PcodeLoweringError(f"{address}: RETURN must be the final operation of a TERMINATOR")
        last_opcode = operations[-1].get("opcode") if operations else None
        if flow_type == "TERMINATOR" and last_opcode != "RETURN":
            raise PcodeLoweringError(f"{address}: terminator is not a supported P-code RETURN")
        if flow_type == "CONDITIONAL_JUMP" and not any(op.get("opcode") == "CBRANCH" for op in operations):
            raise PcodeLoweringError(f"{address}: conditional jump does not end in CBRANCH")
        if flow_type == "UNCONDITIONAL_JUMP" and last_opcode != "BRANCH":
            raise PcodeLoweringError(f"{address}: unconditional jump does not end in BRANCH")
        expected_terminal_opcode = {
            "UNCONDITIONAL_CALL": "CALL", "COMPUTED_CALL": "CALLIND",
            "COMPUTED_JUMP": "BRANCHIND",
        }.get(flow_type)
        if expected_terminal_opcode is not None and last_opcode != expected_terminal_opcode:
            raise PcodeLoweringError(f"{address}: {flow_type} does not end in {expected_terminal_opcode}")
        if flow_type == "CALL_TERMINATOR" and last_opcode not in {"BRANCH", "CALL"}:
            raise PcodeLoweringError(f"{address}: CALL_TERMINATOR does not end in BRANCH or CALL")
        if flow_type == "COMPUTED_CALL_TERMINATOR" and last_opcode not in {"BRANCHIND", "CALLIND"}:
            raise PcodeLoweringError(f"{address}: COMPUTED_CALL_TERMINATOR does not end in BRANCHIND or CALLIND")
        if flow_type == "FALL_THROUGH" and last_opcode in {
            "BRANCH", "CBRANCH", "BRANCHIND", "RETURN", "CALL", "CALLIND",
        } and not ((last_opcode == "BRANCH" and repeat_loop) or
                   (last_opcode == "CBRANCH" and fallthrough_branch) or
                   (len(operations) - 1 in relative_branch_indices)):
            raise PcodeLoweringError(f"{address}: fall-through instruction ends in a control transfer")

    function_value = _hex(function_address, "function address")
    function_symbol = f"rvi_{function_value:08x}"
    lines = [
        f"/* Generated from raw P-code for {function.get('name', function_address)} ({function_address}). */",
        *([_RUNTIME.rstrip()] if include_runtime else []),
        f"int {function_symbol}(RviPcodeContext *ctx) {{",
        f"    uint8_t _unique[{max(unique_size, 1)}] = {{0}};",
        f"    const size_t _unique_size = {unique_size};",
        "    if (!ctx) return -1;",
        *body,
        "    return 0;",
        "}",
    ]
    return "\n".join(lines) + "\n", operation_count


def compile_from_corpus(
    corpus_path: Path,
    manifest_path: Path,
    spaces_path: Path,
    function_address: str,
) -> tuple[str, int]:
    manifest = _json_object(manifest_path)
    spaces = _json_object(spaces_path)
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{manifest_path}: expected {MANIFEST_FORMAT}")
    if spaces.get("format") != SPACES_FORMAT:
        raise ValueError(f"{spaces_path}: expected {SPACES_FORMAT}")
    if not isinstance(manifest.get("output_sha256"), str) or manifest["output_sha256"].lower() != _sha256(corpus_path):
        raise ValueError("corpus manifest SHA-256 does not match the instruction corpus")
    language_id = manifest.get("language_id")
    if not isinstance(language_id, str) or spaces.get("language_id") != language_id:
        raise ValueError("address-space table language id does not match the corpus manifest")
    target = _hex(function_address if function_address.lower().startswith("0x") else "0x" + function_address,
                  "function address")
    with _open_text(corpus_path) as stream:
        for line_no, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{corpus_path}:{line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(row, dict) or row.get("format") != CORPUS_FORMAT:
                raise ValueError(f"{corpus_path}:{line_no}: expected {CORPUS_FORMAT}")
            function = row.get("function")
            if not isinstance(function, dict) or not isinstance(function.get("address"), str):
                continue
            if _hex(function["address"], f"{corpus_path}:{line_no} function address") != target:
                continue
            if row.get("program") != manifest.get("program"):
                raise ValueError(f"{corpus_path}:{line_no}: program differs from corpus manifest")
            return compile_function(row, spaces)
    raise ValueError(f"function {function_address} was not found in the corpus")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Ghidra function-instruction JSONL or JSONL.GZ")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("address_spaces", type=Path)
    parser.add_argument("function_address", help="function entry address, e.g. 0x00401000")
    parser.add_argument("--output", type=Path, required=True, help="write generated C source here")
    args = parser.parse_args(argv)
    try:
        source, operation_count = compile_from_corpus(
            args.corpus, args.manifest, args.address_spaces, args.function_address)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(source, encoding="utf-8")
    print("compiled P-code operations:", operation_count)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
