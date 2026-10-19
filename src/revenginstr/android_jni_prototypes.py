"""Export exact native prototypes from Android DEX declarations and JNI symbols."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.AndroidJniPrototypeEvidence/1"
PROGRAM_INDEX_FORMAT = "REVENGINSTR.GhidraProgramIndex.Functions/1"
DEX_METHOD_FORMAT = "REVENGINSTR.AndroidDexMethod/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_DEX_MAGIC = re.compile(rb"dex\n0(?:3[5-9]|4[0-1])\x00$")
_PRIMITIVE_WIDTHS = {"Z": 1, "B": 1, "C": 2, "S": 2, "I": 4, "J": 8, "F": 4, "D": 8}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("truncated DEX ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("oversized DEX ULEB128 value")


def _mutf8(data: bytes) -> str:
    """Decode the modified UTF-8 used by DEX string_data items."""
    units = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        offset += 1
        if first == 0:
            break
        if first < 0x80:
            units.append(first)
        elif first & 0xe0 == 0xc0:
            if offset >= len(data):
                raise ValueError("truncated DEX modified UTF-8 sequence")
            second = data[offset]
            offset += 1
            if second & 0xc0 != 0x80:
                raise ValueError("invalid DEX modified UTF-8 continuation")
            units.append(((first & 0x1f) << 6) | (second & 0x3f))
        elif first & 0xf0 == 0xe0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DEX modified UTF-8 sequence")
            second, third = data[offset], data[offset + 1]
            offset += 2
            if second & 0xc0 != 0x80 or third & 0xc0 != 0x80:
                raise ValueError("invalid DEX modified UTF-8 continuation")
            units.append(((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f))
        else:
            raise ValueError("invalid DEX modified UTF-8 lead byte")
    raw = b"".join(struct.pack("<H", unit) for unit in units)
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise ValueError("invalid DEX UTF-16 string") from error


def _u32(data: bytes, offset: int, where: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"DEX {where} is outside the file")
    return struct.unpack_from("<I", data, offset)[0]


def _section(data: bytes, size: int, offset: int, item_size: int, where: str) -> None:
    if type(size) is not int or type(offset) is not int or size < 0 or offset < 0:
        raise ValueError(f"invalid DEX {where} bounds")
    if size and (offset == 0 or offset + size * item_size > len(data)):
        raise ValueError(f"DEX {where} is outside the file")


def _descriptor_types(descriptor: str, *, allow_void: bool) -> list[str]:
    values = []
    offset = 0
    while offset < len(descriptor):
        start = offset
        while offset < len(descriptor) and descriptor[offset] == "[":
            offset += 1
        if offset >= len(descriptor):
            raise ValueError("invalid DEX type descriptor")
        kind = descriptor[offset]
        if kind == "L":
            end = descriptor.find(";", offset + 1)
            if end < 0 or end == offset + 1:
                raise ValueError("invalid DEX object descriptor")
            body = descriptor[offset + 1:end]
            if any(char in ".;[" for char in body):
                raise ValueError("invalid DEX object descriptor")
            offset = end + 1
        elif kind in _PRIMITIVE_WIDTHS or (allow_void and kind == "V" and offset == start):
            offset += 1
        else:
            raise ValueError("invalid DEX primitive descriptor")
        values.append(descriptor[start:offset])
    return values


def _method_descriptor(value: str) -> tuple[list[str], str]:
    if not isinstance(value, str) or not value.startswith("("):
        raise ValueError("invalid DEX method descriptor")
    close = value.find(")")
    if close < 0:
        raise ValueError("invalid DEX method descriptor")
    args = _descriptor_types(value[1:close], allow_void=False)
    returns = _descriptor_types(value[close + 1:], allow_void=True)
    if len(returns) != 1:
        raise ValueError("invalid DEX return descriptor")
    return args, returns[0]


def _dex_shape(descriptor: str, pointer_width: int) -> dict[str, Any]:
    if descriptor.startswith(("L", "[")):
        return {"kind": "pointer", "width_bytes": pointer_width}
    if descriptor == "V":
        return {"kind": "void", "width_bytes": None}
    return {"kind": "scalar", "width_bytes": _PRIMITIVE_WIDTHS[descriptor]}


def _read_dex(data: bytes, dex_entry: str) -> list[dict[str, Any]]:
    if len(data) < 0x70 or not _DEX_MAGIC.fullmatch(data[:8]):
        raise ValueError(f"{dex_entry}: unsupported or truncated DEX header")
    file_size = _u32(data, 0x20, "file_size")
    header_size = _u32(data, 0x24, "header_size")
    endian_tag = _u32(data, 0x28, "endian_tag")
    if file_size != len(data) or header_size != 0x70 or endian_tag != 0x12345678:
        raise ValueError(f"{dex_entry}: inconsistent or unsupported DEX header")

    string_count, string_off = _u32(data, 0x38, "string_ids_size"), _u32(data, 0x3c, "string_ids_off")
    type_count, type_off = _u32(data, 0x40, "type_ids_size"), _u32(data, 0x44, "type_ids_off")
    proto_count, proto_off = _u32(data, 0x48, "proto_ids_size"), _u32(data, 0x4c, "proto_ids_off")
    method_count, method_off = _u32(data, 0x58, "method_ids_size"), _u32(data, 0x5c, "method_ids_off")
    class_count, class_off = _u32(data, 0x60, "class_defs_size"), _u32(data, 0x64, "class_defs_off")
    for size, offset, stride, name in (
        (string_count, string_off, 4, "string_ids"), (type_count, type_off, 4, "type_ids"),
        (proto_count, proto_off, 12, "proto_ids"), (method_count, method_off, 8, "method_ids"),
        (class_count, class_off, 32, "class_defs"),
    ):
        _section(data, size, offset, stride, name)

    strings = []
    for index in range(string_count):
        at = _u32(data, string_off + index * 4, "string id")
        utf16_length, at = _uleb128(data, at)
        end = data.find(b"\x00", at)
        if end < 0:
            raise ValueError(f"{dex_entry}: unterminated DEX string")
        value = _mutf8(data[at:end])
        if len(value.encode("utf-16-le")) // 2 != utf16_length:
            raise ValueError(f"{dex_entry}: DEX string length does not match its header")
        strings.append(value)

    types = []
    for index in range(type_count):
        string_index = _u32(data, type_off + index * 4, "type id")
        if string_index >= len(strings):
            raise ValueError(f"{dex_entry}: invalid type descriptor string index")
        types.append(strings[string_index])

    protos = []
    for index in range(proto_count):
        at = proto_off + index * 12
        shorty_index, return_type_index, parameters_off = struct.unpack_from("<III", data, at)
        if shorty_index >= len(strings) or return_type_index >= len(types):
            raise ValueError(f"{dex_entry}: invalid DEX prototype index")
        parameters = []
        if parameters_off:
            count = _u32(data, parameters_off, "type list size")
            if parameters_off + 4 + count * 2 > len(data):
                raise ValueError(f"{dex_entry}: DEX type list is outside the file")
            for item in range(count):
                type_index = struct.unpack_from("<H", data, parameters_off + 4 + item * 2)[0]
                if type_index >= len(types):
                    raise ValueError(f"{dex_entry}: invalid DEX parameter type index")
                parameters.append(types[type_index])
        descriptor = "(" + "".join(parameters) + ")" + types[return_type_index]
        _method_descriptor(descriptor)
        protos.append(descriptor)

    methods = []
    for index in range(method_count):
        class_index, proto_index, name_index = struct.unpack_from("<HHI", data, method_off + index * 8)
        if class_index >= len(types) or proto_index >= len(protos) or name_index >= len(strings):
            raise ValueError(f"{dex_entry}: invalid DEX method id index")
        methods.append((class_index, proto_index, name_index))

    native_rows = []
    seen_method_ids = set()
    for class_index in range(class_count):
        at = class_off + class_index * 32
        defined_class, _, _, _, _, _, class_data_off, _ = struct.unpack_from("<IIIIIIII", data, at)
        if defined_class >= len(types):
            raise ValueError(f"{dex_entry}: invalid DEX class definition")
        if class_data_off == 0:
            continue
        counts = []
        offset = class_data_off
        for _ in range(4):
            count, offset = _uleb128(data, offset)
            counts.append(count)
        static_fields, instance_fields, direct_methods, virtual_methods = counts
        for _ in range(static_fields + instance_fields):
            _, offset = _uleb128(data, offset)
            _, offset = _uleb128(data, offset)
        for method_group_count in (direct_methods, virtual_methods):
            method_index = 0
            for _ in range(method_group_count):
                delta, offset = _uleb128(data, offset)
                access_flags, offset = _uleb128(data, offset)
                _, offset = _uleb128(data, offset)  # code_off
                method_index += delta
                if method_index >= len(methods):
                    raise ValueError(f"{dex_entry}: class data references an invalid method id")
                if access_flags & 0x100 == 0:
                    continue
                if method_index in seen_method_ids:
                    raise ValueError(f"{dex_entry}: duplicate native method id in class data")
                seen_method_ids.add(method_index)
                method_class, proto_index, name_index = methods[method_index]
                if method_class != defined_class:
                    raise ValueError(f"{dex_entry}: method class does not match class data")
                native_rows.append({
                    "dex_entry": dex_entry,
                    "dex_sha256": _sha(data),
                    "dex_method_index": method_index,
                    "class_descriptor": types[defined_class],
                    "method_name": strings[name_index],
                    "method_descriptor": protos[proto_index],
                    "is_static": bool(access_flags & 0x8),
                })
    return native_rows


def _jni_escape(value: str) -> str:
    pieces = []
    for char in value:
        codepoint = ord(char)
        if char == "/":
            pieces.append("_")
        elif char == "_":
            pieces.append("_1")
        elif char == ";":
            pieces.append("_2")
        elif char == "[":
            pieces.append("_3")
        elif char.isascii() and char.isalnum():
            pieces.append(char)
        elif codepoint <= 0xffff:
            pieces.append(f"_0{codepoint:04x}")
        else:
            codepoint -= 0x10000
            pieces.extend((f"_0{0xd800 + (codepoint >> 10):04x}", f"_0{0xdc00 + (codepoint & 0x3ff):04x}"))
    return "".join(pieces)


def _jni_symbol(method: dict[str, Any], overloaded: bool) -> str:
    class_name = _jni_escape(method["class_descriptor"][1:-1])
    method_name = _jni_escape(method["method_name"])
    short_name = f"Java_{class_name}_{method_name}"
    if not overloaded:
        return short_name
    arguments, _ = _method_descriptor(method["method_descriptor"])
    descriptor = "".join(arguments)
    return short_name + "__" + _jni_escape(descriptor)


def _read_program_identity(path: Path) -> tuple[dict[str, Any], dict[tuple[str, int], dict[str, Any]]]:
    functions = {}
    metadata = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: decompiler input is not UTF-8") from error
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
        if not isinstance(row, dict) or row.get("format") != "REVENGINSTR.GhidraDecompilerParameters/1":
            raise ValueError(f"{path}:{line_no}: expected GhidraDecompilerParameters/1")
        current = {
            "program_id": row.get("program_id"),
            "program_sha256": row.get("program_sha256"),
            "architecture": row.get("architecture"),
        }
        if metadata is None:
            metadata = current
        elif metadata != current:
            raise ValueError(f"{path}:{line_no}: decompiler records have different program identities")
        if not isinstance(row.get("function_entry"), str) or not _ADDRESS.fullmatch(row["function_entry"]):
            raise ValueError(f"{path}:{line_no}: invalid function_entry")
        try:
            entry_key = int(row["function_entry"].removeprefix("0x"), 16)
        except ValueError as error:
            raise ValueError(f"{path}:{line_no}: invalid function_entry") from error
        if ("", entry_key) in functions:
            raise ValueError(f"{path}:{line_no}: duplicate function entry")
        functions[("", entry_key)] = row
    if metadata is None:
        raise ValueError(f"{path}: decompiler input is empty")
    if not isinstance(metadata["program_id"], str) or not metadata["program_id"]:
        raise ValueError(f"{path}: missing program_id")
    if not isinstance(metadata["program_sha256"], str) or not _SHA256.fullmatch(metadata["program_sha256"]):
        raise ValueError(f"{path}: invalid program_sha256")
    architecture = metadata["architecture"]
    if not isinstance(architecture, dict) or set(architecture) != {"language_id", "pointer_width_bytes", "endianness"}:
        raise ValueError(f"{path}: invalid architecture")
    if not isinstance(architecture["language_id"], str) or not architecture["language_id"]:
        raise ValueError(f"{path}: invalid architecture language_id")
    if type(architecture["pointer_width_bytes"]) is not int or architecture["pointer_width_bytes"] < 1:
        raise ValueError(f"{path}: invalid architecture pointer width")
    if architecture["endianness"] not in {"little", "big"}:
        raise ValueError(f"{path}: invalid architecture endianness")
    return metadata, functions


def _read_function_index(path: Path) -> tuple[dict[str, list[tuple[int, dict[str, str]]]], str]:
    raw = path.read_bytes()
    digest = _sha(raw)
    try:
        content = gzip.decompress(raw).decode("utf-8") if raw.startswith(b"\x1f\x8b") else raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"{path}: invalid Ghidra function index: {error}") from error
    rows = list(csv.DictReader(io.StringIO(content), delimiter="\t", strict=True))
    if not rows or list(rows[0]) != ["entry", "name", "address_count", "is_external", "signature"]:
        raise ValueError(f"{path}: invalid GhidraProgramIndex.Functions/1 header")
    by_name: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for record_index, row in enumerate(rows, 1):
        if not _ADDRESS.fullmatch(row["entry"]):
            raise ValueError(f"{path}: invalid function entry on record {record_index}")
        if row["is_external"] not in {"true", "false"}:
            raise ValueError(f"{path}: invalid is_external value on record {record_index}")
        if row["is_external"] == "true":
            continue
        by_name.setdefault(row["name"], []).append((record_index, row))
    return by_name, digest


def _shape_for_method(method: dict[str, Any], pointer_width: int) -> tuple[list[dict[str, Any]], dict[str, Any], int | None]:
    argument_types, return_type = _method_descriptor(method["method_descriptor"])
    parameters = [
        {"index": 0, "role": "jni_environment", "java_parameter_index": None,
         "kind": "pointer", "width_bytes": pointer_width},
        {"index": 1, "role": "jni_class" if method["is_static"] else "jni_receiver",
         "java_parameter_index": None, "kind": "pointer", "width_bytes": pointer_width},
    ]
    for java_index, descriptor in enumerate(argument_types):
        shape = _dex_shape(descriptor, pointer_width)
        parameters.append({
            "index": len(parameters), "role": "java_argument", "java_parameter_index": java_index,
            **shape,
        })
    return parameters, _dex_shape(return_type, pointer_width), None if method["is_static"] else 1


def validate_row(row: Any, where: str) -> None:
    expected = {
        "format", "program_id", "program_sha256", "architecture", "function_entry", "jni_symbol",
        "apk_sha256", "library_entry", "library_sha256", "dex_entry", "dex_sha256",
        "dex_method_index", "class_descriptor", "method_name", "method_descriptor", "is_static",
        "parameter_count", "parameters", "return_value", "receiver_parameter_index", "evidence_refs",
    }
    if not isinstance(row, dict) or set(row) != expected or row.get("format") != FORMAT:
        raise ValueError(f"{where}: invalid {FORMAT} fields")
    for field in ("program_id", "jni_symbol", "library_entry", "dex_entry", "class_descriptor", "method_name"):
        if not isinstance(row[field], str) or not row[field]:
            raise ValueError(f"{where}: {field} must be a non-empty string")
    for field in ("program_sha256", "apk_sha256", "library_sha256", "dex_sha256"):
        if not isinstance(row[field], str) or not _SHA256.fullmatch(row[field]):
            raise ValueError(f"{where}: invalid {field}")
    if row["library_sha256"] != row["program_sha256"]:
        raise ValueError(f"{where}: APK library does not match the Ghidra program")
    if not isinstance(row["function_entry"], str) or not _ADDRESS.fullmatch(row["function_entry"]):
        raise ValueError(f"{where}: invalid function_entry")
    architecture = row["architecture"]
    if not isinstance(architecture, dict) or set(architecture) != {"language_id", "pointer_width_bytes", "endianness"}:
        raise ValueError(f"{where}: invalid architecture")
    pointer_width = architecture["pointer_width_bytes"]
    if type(pointer_width) is not int or pointer_width < 1 or architecture["endianness"] not in {"little", "big"}:
        raise ValueError(f"{where}: invalid architecture details")
    if type(row["dex_method_index"]) is not int or row["dex_method_index"] < 0:
        raise ValueError(f"{where}: invalid dex_method_index")
    if not isinstance(row["is_static"], bool):
        raise ValueError(f"{where}: is_static must be boolean")
    if not isinstance(row["class_descriptor"], str) or not row["class_descriptor"].startswith("L") or not row["class_descriptor"].endswith(";"):
        raise ValueError(f"{where}: invalid class_descriptor")
    arguments, return_type = _method_descriptor(row["method_descriptor"])
    method = {
        "class_descriptor": row["class_descriptor"], "method_name": row["method_name"],
        "method_descriptor": row["method_descriptor"], "is_static": row["is_static"],
    }
    short = _jni_symbol(method, False)
    long = _jni_symbol(method, True)
    if row["jni_symbol"] not in {short, long}:
        raise ValueError(f"{where}: jni_symbol does not encode the DEX method")
    parameters, expected_return, receiver = _shape_for_method(method, pointer_width)
    if row["parameter_count"] != len(arguments) + 2 or type(row["parameter_count"]) is not int:
        raise ValueError(f"{where}: parameter_count does not match the JNI method")
    if row["receiver_parameter_index"] != receiver:
        raise ValueError(f"{where}: receiver_parameter_index does not match method staticness")
    if not isinstance(row["parameters"], list) or row["parameters"] != parameters:
        raise ValueError(f"{where}: parameters do not match the DEX descriptor")
    if row["return_value"] != expected_return:
        raise ValueError(f"{where}: return_value does not match the DEX descriptor")
    refs = row["evidence_refs"]
    if not isinstance(refs, list) or len(refs) != 2:
        raise ValueError(f"{where}: expected DEX and Ghidra function-index references")
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"artifact_sha256", "record_index", "source_format"}:
            raise ValueError(f"{where}: invalid evidence reference")
        if not isinstance(ref["artifact_sha256"], str) or not _SHA256.fullmatch(ref["artifact_sha256"]):
            raise ValueError(f"{where}: invalid evidence-reference hash")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{where}: invalid evidence-reference record index")
    dex_ref, index_ref = refs
    if dex_ref != {
        "artifact_sha256": row["dex_sha256"], "record_index": row["dex_method_index"] + 1,
        "source_format": DEX_METHOD_FORMAT,
    }:
        raise ValueError(f"{where}: DEX evidence reference does not identify this method")
    if index_ref["source_format"] != PROGRAM_INDEX_FORMAT:
        raise ValueError(f"{where}: unsupported function-index source format")


def export_android_jni_prototypes(
    apk_path: Path, function_index_path: Path, decompiler_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    apk_raw = apk_path.read_bytes()
    apk_sha = _sha(apk_raw)
    metadata, selected_functions = _read_program_identity(decompiler_path)
    function_rows, function_index_sha = _read_function_index(function_index_path)
    pointer_width = metadata["architecture"]["pointer_width_bytes"]

    try:
        archive = zipfile.ZipFile(io.BytesIO(apk_raw))
    except zipfile.BadZipFile as error:
        raise ValueError(f"{apk_path}: expected an Android APK ZIP archive") from error
    with archive:
        dex_names = sorted(
            (name for name in archive.namelist() if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", Path(name).name)),
            key=lambda name: (0 if Path(name).name == "classes.dex" else int(Path(name).stem[7:]), name),
        )
        if not dex_names:
            raise ValueError(f"{apk_path}: no classes*.dex files found")
        library_matches = []
        for name in archive.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                content = archive.read(name)
                if _sha(content) == metadata["program_sha256"]:
                    library_matches.append(name)
        if not library_matches:
            raise ValueError(f"{apk_path}: no native library matches the Ghidra executable SHA-256")
        library_entry = sorted(library_matches)[0]
        dex_methods = []
        for dex_entry in dex_names:
            dex_methods.extend(_read_dex(archive.read(dex_entry), dex_entry))

    overloaded = {}
    for method in dex_methods:
        key = (method["class_descriptor"], method["method_name"])
        overloaded[key] = overloaded.get(key, 0) + 1

    rows = []
    matched = selected = ambiguous = 0
    for method in dex_methods:
        overloaded_name = overloaded[(method["class_descriptor"], method["method_name"])] > 1
        symbol = _jni_symbol(method, overloaded_name)
        candidates = function_rows.get(symbol, [])
        if not candidates:
            continue
        if len(candidates) != 1:
            ambiguous += 1
            continue
        matched += 1
        index_record, function = candidates[0]
        entry_key = ("", int(function["entry"].removeprefix("0x"), 16))
        decompiler = selected_functions.get(entry_key)
        if decompiler is None:
            continue
        selected += 1
        parameters, return_value, receiver = _shape_for_method(method, pointer_width)
        row = {
            "format": FORMAT,
            "program_id": metadata["program_id"],
            "program_sha256": metadata["program_sha256"],
            "architecture": metadata["architecture"],
            "function_entry": decompiler["function_entry"],
            "jni_symbol": symbol,
            "apk_sha256": apk_sha,
            "library_entry": library_entry,
            "library_sha256": metadata["program_sha256"],
            "dex_entry": method["dex_entry"],
            "dex_sha256": method["dex_sha256"],
            "dex_method_index": method["dex_method_index"],
            "class_descriptor": method["class_descriptor"],
            "method_name": method["method_name"],
            "method_descriptor": method["method_descriptor"],
            "is_static": method["is_static"],
            "parameter_count": len(parameters),
            "parameters": parameters,
            "return_value": return_value,
            "receiver_parameter_index": receiver,
            "evidence_refs": [
                {"artifact_sha256": method["dex_sha256"], "record_index": method["dex_method_index"] + 1,
                 "source_format": DEX_METHOD_FORMAT},
                {"artifact_sha256": function_index_sha, "record_index": index_record,
                 "source_format": PROGRAM_INDEX_FORMAT},
            ],
        }
        validate_row(row, f"{apk_path}:{symbol}")
        rows.append(row)
    rows.sort(key=lambda row: int(row["function_entry"].removeprefix("0x"), 16))
    return rows, {
        "dex_native_methods": len(dex_methods), "matching_exported_symbols": matched,
        "selected_functions": selected, "ambiguous_symbols": ambiguous,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, help="APK containing the exact Ghidra-analyzed native library")
    parser.add_argument("function_index", type=Path, help="GhidraProgramIndex/1 functions TSV or TSV.GZ")
    parser.add_argument("decompiler_parameters", type=Path, help="GhidraDecompilerParameters/1 JSONL")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {args.apk.resolve(), args.function_index.resolve(), args.decompiler_parameters.resolve()}
    if args.output.resolve() in inputs:
        print("error: output path must differ from every input path", file=sys.stderr)
        return 2
    try:
        rows, counts = export_android_jni_prototypes(args.apk, args.function_index, args.decompiler_parameters)
    except (OSError, ValueError, zipfile.BadZipFile, csv.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print("format:", FORMAT)
    print("DEX native methods:", counts["dex_native_methods"])
    print("matching exported symbols:", counts["matching_exported_symbols"])
    print("selected functions:", counts["selected_functions"])
    print("ambiguous symbols:", counts["ambiguous_symbols"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
