from __future__ import annotations

import gzip
import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from revenginstr.pcode.c_lowering import PcodeLoweringError, compile_from_corpus, compile_function


def _varnode(space: str, offset: str, size: int, *, constant: bool = False) -> dict:
    return {"space": space, "offset": offset, "size": size, "constant": constant}


def _address_spaces() -> dict:
    return {
        "format": "REVENGINSTR.GhidraLanguageAddressSpaces/1",
        "language_id": "x86:LE:32:default",
        "big_endian": False,
        "default_space": "ram",
        "default_data_space": "ram",
        "address_spaces": [{
            "space_id": "0x1a1",
            "name": "ram",
            "pointer_size": 4,
            "addressable_unit_size": 1,
            "memory": True,
            "loaded_memory": True,
            "constant": False,
            "register": False,
            "stack": False,
            "unique": False,
            "external": False,
            "overlay": False,
        }],
    }


def _function_row() -> dict:
    constant = lambda value, size=4: _varnode("const", hex(value), size, constant=True)
    unique = _varnode("unique", "0x100", 4)
    eax = _varnode("register", "0x0", 4)
    output = _varnode("register", "0x4", 4)
    memory_id = _varnode("const", "0x1a1", 4, constant=True)
    pointer = constant(0x100)
    return {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "requested": "0x00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "function": {"address": "0x00401000", "name": "sample", "size": 16, "calling_convention": None},
        "instruction_count": 5,
        "instructions": [
            {"address": "0x00401000", "mnemonic": "ADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [
                {"opcode": "INT_ADD", "output": unique, "inputs": [constant(7), constant(2)]},
            ]},
            {"address": "0x00401004", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [
                {"opcode": "STORE", "output": None, "inputs": [memory_id, pointer, unique]},
            ]},
            {"address": "0x00401008", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [
                {"opcode": "LOAD", "output": eax, "inputs": [memory_id, pointer]},
            ]},
            {"address": "0x0040100c", "mnemonic": "IMUL", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [
                {"opcode": "INT_MULT", "output": output, "inputs": [eax, constant(2)]},
            ]},
            {"address": "0x00401010", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [
                {"opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)]},
            ]},
        ],
    }


def test_codegen_emits_native_c_with_memory_and_register_callbacks(tmp_path: Path) -> None:
    row = _function_row()
    spaces = _address_spaces()
    source, operation_count = compile_function(row, spaces)
    assert operation_count == 5
    assert "int rvi_00401000" in source
    assert "rvi_read_space(ctx, \"ram\"" in source
    assert "rvi_write_space(ctx, \"ram\"" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
#include <stdio.h>
typedef struct { uint8_t registers[64]; uint8_t ram[512]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    if (!base || offset + size > 512) return -1;
    memcpy(out, base + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    if (!base || offset + size > 512) return -1;
    memcpy(base + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}, {0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t stored = 0, result = 0;
    memcpy(&stored, state.ram + 0x100, sizeof(stored));
    memcpy(&result, state.registers + 4, sizeof(result));
    if (stored != 9 || result != 18) return 2;
    return 0;
}
'''
    c_path = tmp_path / "compiled.c"
    executable = tmp_path / "compiled"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


@pytest.mark.parametrize("big_endian", [False, True])
def test_codegen_executes_16_byte_data_operations(tmp_path: Path, big_endian: bool) -> None:
    spaces = _address_spaces()
    spaces["big_endian"] = big_endian
    endianness = "big" if big_endian else "little"
    memory_value = bytes(range(16))
    xor_value = int.from_bytes(memory_value, endianness) ^ 0xff
    xor_bytes = xor_value.to_bytes(16, endianness)
    shifted_bytes = (xor_value >> 4).to_bytes(16, endianness)
    extended_bytes = (0x12345678).to_bytes(16, endianness)
    inverted_bytes = ((~xor_value) & ((1 << 128) - 1)).to_bytes(16, endianness)

    def instruction(index: int, opcode: str, output: dict | None, inputs: list[dict], *, terminal: bool = False) -> dict:
        return {
            "address": f"0x004010{index:02x}",
            "mnemonic": opcode,
            "flow_type": "TERMINATOR" if terminal else "FALL_THROUGH",
            "flows": [],
            "pcode": [{"opcode": opcode, "output": output, "inputs": inputs}],
        }

    memory_id = _varnode("const", "0x1a1", 4, constant=True)
    row = _function_row()
    row["instructions"] = [
        instruction(0, "LOAD", _varnode("unique", "0x200", 16), [memory_id, _varnode("const", "0x100", 4, constant=True)]),
        instruction(1, "INT_XOR", _varnode("register", "0x1200", 16), [
            _varnode("unique", "0x200", 16), _varnode("const", "0xff", 16, constant=True),
        ]),
        instruction(2, "STORE", None, [memory_id, _varnode("const", "0x120", 4, constant=True), _varnode("register", "0x1200", 16)]),
        instruction(3, "INT_RIGHT", _varnode("unique", "0x220", 16), [
            _varnode("register", "0x1200", 16), _varnode("const", "0x4", 4, constant=True),
        ]),
        instruction(4, "STORE", None, [memory_id, _varnode("const", "0x140", 4, constant=True), _varnode("unique", "0x220", 16)]),
        instruction(5, "SUBPIECE", _varnode("register", "0x1300", 4), [
            _varnode("register", "0x1200", 16), _varnode("const", "0x0", 4, constant=True),
        ]),
        instruction(6, "INT_ZEXT", _varnode("unique", "0x240", 16), [
            _varnode("const", "0x12345678", 4, constant=True),
        ]),
        instruction(7, "STORE", None, [memory_id, _varnode("const", "0x160", 4, constant=True), _varnode("unique", "0x240", 16)]),
        instruction(8, "INT_NEGATE", _varnode("register", "0x1240", 16), [_varnode("register", "0x1200", 16)]),
        instruction(9, "RETURN", None, [_varnode("register", "0x20", 4)], terminal=True),
    ]
    row["instruction_count"] = len(row["instructions"])
    source, operation_count = compile_function(row, spaces)
    assert operation_count == 10

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    def c_bytes(value: bytes) -> str:
        return ", ".join(f"0x{byte:02x}" for byte in value)
    harness = f'''
typedef struct {{ uint8_t registers[0x2000]; uint8_t ram[0x200]; }} TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {{
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(out, base + offset, size);
    return 0;
}}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {{
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(base + offset, in, size);
    return 0;
}}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {{
    TestState state = {{{{0}}, {{0}}}};
    const uint8_t input[16] = {{{c_bytes(memory_value)}}};
    const uint8_t expected_xor[16] = {{{c_bytes(xor_bytes)}}};
    const uint8_t expected_shift[16] = {{{c_bytes(shifted_bytes)}}};
    const uint8_t expected_extend[16] = {{{c_bytes(extended_bytes)}}};
    const uint8_t expected_invert[16] = {{{c_bytes(inverted_bytes)}}};
    memcpy(state.ram + 0x100, input, sizeof(input));
    RviPcodeContext context = {{&state, read_bytes, write_bytes, NULL, NULL}};
    if (rvi_00401000(&context) != 0) return 1;
    if (memcmp(state.registers + 0x1200, expected_xor, 16) != 0 ||
        memcmp(state.ram + 0x120, expected_xor, 16) != 0 ||
        memcmp(state.ram + 0x140, expected_shift, 16) != 0 ||
        memcmp(state.ram + 0x160, expected_extend, 16) != 0 ||
        memcmp(state.registers + 0x1240, expected_invert, 16) != 0) return 2;
    if (memcmp(state.registers + 0x1300, expected_xor + {12 if big_endian else 0}, 4) != 0) return 3;
    return 0;
}}
'''
    c_path = tmp_path / "opaque16.c"
    executable = tmp_path / "opaque16"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_executes_float_arithmetic_and_signed_conversions(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 7
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "FADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT_ADD", "output": _varnode("unique", "0x100", 4),
            "inputs": [_varnode("const", "0x3fc00000", 4, constant=True),
                       _varnode("const", "0x40100000", 4, constant=True)],
        }]},
        {"address": "0x00401001", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("unique", "0x100", 4)],
        }]},
        {"address": "0x00401002", "mnemonic": "FCMP", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT_NOTEQUAL", "output": _varnode("register", "0x8", 1),
            "inputs": [_varnode("const", "0x7fc00000", 4, constant=True),
                       _varnode("const", "0x3f800000", 4, constant=True)],
        }]},
        {"address": "0x00401003", "mnemonic": "FIST", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "TRUNC", "output": _varnode("register", "0xc", 4),
            "inputs": [_varnode("unique", "0x100", 4)],
        }]},
        {"address": "0x00401004", "mnemonic": "CVTSI2SD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "INT2FLOAT", "output": _varnode("unique", "0x200", 8),
            "inputs": [_varnode("const", "0xfffffff9", 4, constant=True)],
        }]},
        {"address": "0x00401005", "mnemonic": "CVTSD2SS", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("register", "0x10", 4),
            "inputs": [_varnode("unique", "0x200", 8)],
        }]},
        {"address": "0x00401006", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 7

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; uint8_t ram[512]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t float_sum = 0, integer_truncation = 0, float_conversion = 0;
    memcpy(&float_sum, state.registers + 4, sizeof(float_sum));
    memcpy(&integer_truncation, state.registers + 0xc, sizeof(integer_truncation));
    memcpy(&float_conversion, state.registers + 0x10, sizeof(float_conversion));
    if (float_sum != 0x40700000 || state.registers[8] != 0) return 2;
    if (integer_truncation != 3 || float_conversion != 0xc0e00000) return 3;
    return 0;
}
'''
    c_path = tmp_path / "float.c"
    executable = tmp_path / "float"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_executes_binary80_conversions_arithmetic_copy_and_truncation(tmp_path: Path) -> None:
    row = _function_row()
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "FLD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("unique", "0x100", 10),
            "inputs": [_varnode("const", "0x3fc00000", 4, constant=True)],
        }]},
        {"address": "0x00401001", "mnemonic": "FLD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("unique", "0x120", 10),
            "inputs": [_varnode("const", "0x40100000", 4, constant=True)],
        }]},
        {"address": "0x00401002", "mnemonic": "FADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT_ADD", "output": _varnode("unique", "0x140", 10),
            "inputs": [_varnode("unique", "0x100", 10), _varnode("unique", "0x120", 10)],
        }]},
        {"address": "0x00401003", "mnemonic": "FCMP", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT_EQUAL", "output": _varnode("register", "0x10", 1),
            "inputs": [_varnode("unique", "0x140", 10),
                       _varnode("const", "0x4000f000000000000000", 10, constant=True)],
        }]},
        {"address": "0x00401004", "mnemonic": "FST", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x20", 10),
            "inputs": [_varnode("unique", "0x140", 10)],
        }]},
        {"address": "0x00401005", "mnemonic": "FST", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "STORE", "output": None,
            "inputs": [_varnode("const", "0x1a1", 4, constant=True),
                       _varnode("const", "0x100", 4, constant=True), _varnode("unique", "0x140", 10)],
        }]},
        {"address": "0x00401006", "mnemonic": "FLD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "LOAD", "output": _varnode("register", "0x30", 10),
            "inputs": [_varnode("const", "0x1a1", 4, constant=True),
                       _varnode("const", "0x100", 4, constant=True)],
        }]},
        {"address": "0x00401007", "mnemonic": "FIST", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "TRUNC", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("unique", "0x140", 10)],
        }]},
        {"address": "0x00401008", "mnemonic": "FILD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "INT2FLOAT", "output": _varnode("unique", "0x180", 10),
            "inputs": [_varnode("const", "0xfffffffe", 4, constant=True)],
        }]},
        {"address": "0x00401009", "mnemonic": "FSTP", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("register", "0x8", 4),
            "inputs": [_varnode("unique", "0x180", 10)],
        }]},
        {"address": "0x0040100a", "mnemonic": "FSTP", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("register", "0x0", 4),
            "inputs": [_varnode("unique", "0x140", 10)],
        }]},
        {"address": "0x0040100b", "mnemonic": "FADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT_ADD", "output": _varnode("register", "0x40", 10),
            "inputs": [_varnode("const", "0x1", 10, constant=True),
                       _varnode("const", "0x1", 10, constant=True)],
        }]},
        {"address": "0x0040100c", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    row["instruction_count"] = len(row["instructions"])
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 13

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[128]; uint8_t ram[512]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(out, base + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(base + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}, {0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t sum = 0, truncated = 0, converted = 0;
    memcpy(&sum, state.registers, 4);
    memcpy(&truncated, state.registers + 4, 4);
    memcpy(&converted, state.registers + 8, 4);
    const uint8_t expected80[10] = {0, 0, 0, 0, 0, 0, 0, 0xf0, 0, 0x40};
    if (sum != 0x40700000 || truncated != 3 || converted != 0xc0000000) return 2;
    if (state.registers[0x10] != 1 || memcmp(state.registers + 0x20, expected80, 10) != 0) return 3;
    if (memcmp(state.ram + 0x100, expected80, 10) != 0 ||
        memcmp(state.registers + 0x30, expected80, 10) != 0) return 4;
    const uint8_t expected_subnormal80[10] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (memcmp(state.registers + 0x40, expected_subnormal80, 10) != 0) return 5;
    return 0;
}
'''
    c_path = tmp_path / "binary80.c"
    executable = tmp_path / "binary80"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


@pytest.mark.parametrize(("input_bits", "expected_bits"), [
    ("0x40700000", 0x40400000),
    ("0xc0700000", 0xc0400000),
])
def test_codegen_truncates_binary80_to_an_integral_binary80_value(
    tmp_path: Path, input_bits: str, expected_bits: int,
) -> None:
    row = _function_row()
    row["instruction_count"] = 4
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "FLD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("unique", "0x100", 10),
            "inputs": [_varnode("const", input_bits, 4, constant=True)],
        }]},
        {"address": "0x00401001", "mnemonic": "FRNDINT", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "TRUNC", "output": _varnode("unique", "0x120", 10),
            "inputs": [_varnode("unique", "0x100", 10)],
        }]},
        {"address": "0x00401002", "mnemonic": "FST", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "FLOAT2FLOAT", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("unique", "0x120", 10)],
        }]},
        {"address": "0x00401003", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 4

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = f'''
typedef struct {{ uint8_t registers[64]; }} TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {{
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {{
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {{
    TestState state = {{{{0}}}};
    RviPcodeContext context = {{&state, read_bytes, write_bytes, NULL, NULL}};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t value = 0;
    memcpy(&value, state.registers + 4, sizeof(value));
    return value == UINT32_C(0x{expected_bits:08x}) ? 0 : 2;
}}
'''
    c_path = tmp_path / "binary80-trunc.c"
    executable = tmp_path / "binary80-trunc"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_classifies_unnormal_binary80_as_nan(tmp_path: Path) -> None:
    row = _function_row()
    unnormal = _varnode("const", "0x40000000000000000000", 10, constant=True)
    zero = _varnode("const", "0x0", 10, constant=True)
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "FNAN", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [
            {"opcode": "FLOAT_NAN", "output": _varnode("register", "0x10", 1), "inputs": [unnormal]},
            {"opcode": "FLOAT_NOTEQUAL", "output": _varnode("register", "0x11", 1), "inputs": [unnormal, zero]},
            {"opcode": "FLOAT_EQUAL", "output": _varnode("register", "0x12", 1), "inputs": [unnormal, zero]},
            {"opcode": "FLOAT_LESS", "output": _varnode("register", "0x13", 1), "inputs": [unnormal, zero]},
        ]},
    ]
    row["instruction_count"] = len(row["instructions"])
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 4

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[128]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    return state.registers[0x10] == 1 && state.registers[0x11] == 1 &&
           state.registers[0x12] == 0 && state.registers[0x13] == 0 ? 0 : 2;
}
'''
    c_path = tmp_path / "binary80-unnormal.c"
    executable = tmp_path / "binary80-unnormal"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_clears_fprem_partial_remainder_status(tmp_path: Path) -> None:
    row = _function_row()
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "FPREM", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x10ac", 4),
            "inputs": [_varnode("const", "0x401000", 4, constant=True)],
        }]},
        {"address": "0x00401002", "mnemonic": "FSTSW", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x0", 2),
            "inputs": [_varnode("register", "0x10a2", 2)],
        }]},
    ]
    row["instruction_count"] = len(row["instructions"])
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 3

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[0x2000]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    uint16_t status = UINT16_C(0xffff);
    memcpy(state.registers + 0x10a2, &status, sizeof(status));
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    memcpy(&status, state.registers, sizeof(status));
    return status == UINT16_C(0xfbff) ? 0 : 2;
}
'''
    c_path = tmp_path / "fprem-status.c"
    executable = tmp_path / "fprem-status"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_executes_signed_and_unsigned_division_and_remainder(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 5
    operations = [
        ("INT_DIV", "0x7", "0x2", "0x4"),
        ("INT_REM", "0x7", "0x2", "0x8"),
        ("INT_SDIV", "0xfffffff9", "0x2", "0xc"),
        ("INT_SREM", "0xfffffff9", "0x2", "0x10"),
    ]
    row["instructions"] = [
        {"address": f"0x004010{index:02x}", "mnemonic": opcode, "flow_type": "FALL_THROUGH",
         "flows": [], "pcode": [{
             "opcode": opcode, "output": _varnode("register", out, 4),
             "inputs": [_varnode("const", left, 4, constant=True),
                        _varnode("const", right, 4, constant=True)],
         }]}
        for index, (opcode, left, right, out) in enumerate(operations)
    ] + [{
        "address": "0x00401004", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }],
    }]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 5

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t actual[4] = {0};
    for (unsigned i = 0; i < 4; i++) memcpy(&actual[i], state.registers + 4 + i * 4, 4);
    return actual[0] == 3 && actual[1] == 1 && actual[2] == UINT32_C(0xfffffffd) &&
           actual[3] == UINT32_C(0xffffffff) ? 0 : 2;
}
'''
    c_path = tmp_path / "division.c"
    executable = tmp_path / "division"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_routes_callother_by_language_userop_index(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 2
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "SPECIAL", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "CALLOTHER", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("const", "0x2a", 4, constant=True),
                       _varnode("const", "0x7", 4, constant=True)],
        }]},
        {"address": "0x00401001", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 2
    assert "UINT32_C(42)" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
static int execute_userop(void *opaque, uint32_t index, const uint64_t *args,
                          const unsigned *sizes, size_t count, uint64_t *output, unsigned output_size) {
    (void)opaque;
    if (index != 42 || count != 1 || sizes[0] != 4 || output_size != 4 || !output) return -1;
    *output = index + args[0];
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, execute_userop};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t result = 0;
    memcpy(&result, state.registers + 4, sizeof(result));
    return result == 49 ? 0 : 2;
}
'''
    c_path = tmp_path / "userop.c"
    executable = tmp_path / "userop"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


@pytest.mark.parametrize("big_endian", [False, True])
def test_codegen_routes_wide_callother_arguments_without_changing_context_abi(
    tmp_path: Path, big_endian: bool,
) -> None:
    spaces = _address_spaces()
    spaces["big_endian"] = big_endian
    endian = "big" if big_endian else "little"
    input_bytes = bytes(range(16))
    value = int.from_bytes(input_bytes, endian)
    mask64 = (1 << 64) - 1
    result_value = ((value & mask64) ^ 0x12345678) | (((value >> 64) ^ 0x12345678) << 64)
    expected = result_value.to_bytes(16, endian)
    row = _function_row()
    row["instruction_count"] = 2
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "SPECIAL", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "CALLOTHER", "output": _varnode("register", "0x1200", 16),
            "inputs": [_varnode("const", "0x2a", 4, constant=True),
                       _varnode("register", "0x100", 16),
                       _varnode("const", "0x12345678", 4, constant=True)],
        }]},
        {"address": "0x00401001", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, spaces)
    assert operation_count == 2

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    def c_bytes(data: bytes) -> str:
        return ", ".join(f"0x{byte:02x}" for byte in data)
    harness = f'''
typedef struct {{ uint8_t registers[0x2000]; }} TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {{
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {{
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}}
static int execute_userop(void *opaque, uint32_t index, const uint64_t *args,
                          const unsigned *sizes, size_t count, uint64_t *output, unsigned output_size) {{
    (void)opaque;
    if (index != 42 || count != 2 || sizes[0] != 16 || sizes[1] != 4 || output_size != 16 || !output) return -1;
    output[0] = args[0] ^ args[2];
    output[1] = args[1] ^ args[2];
    return 0;
}}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {{
    TestState state = {{{{0}}}};
    const uint8_t input[16] = {{{c_bytes(input_bytes)}}};
    const uint8_t expected[16] = {{{c_bytes(expected)}}};
    memcpy(state.registers + 0x100, input, sizeof(input));
    RviPcodeContext context = {{&state, read_bytes, write_bytes, NULL, execute_userop}};
    if (rvi_00401000(&context) != 0) return 1;
    return memcmp(state.registers + 0x1200, expected, sizeof(expected)) == 0 ? 0 : 2;
}}
'''
    c_path = tmp_path / "wide-userop.c"
    executable = tmp_path / "wide-userop"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_routes_computed_call_terminator_with_trailing_return(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 1
    row["instructions"] = [{
        "address": "0x00401000", "mnemonic": "BREAK", "flow_type": "COMPUTED_CALL_TERMINATOR",
        "fallthrough": "0x00401001",
        "flows": [], "pcode": [
            {"opcode": "CALLOTHER", "output": _varnode("unique", "0x100", 4),
             "inputs": [_varnode("const", "0x10", 4, constant=True),
                        _varnode("const", "0x1234", 4, constant=True)]},
            {"opcode": "CALLIND", "output": None, "inputs": [_varnode("unique", "0x100", 4)]},
            {"opcode": "RETURN", "output": None, "inputs": [_varnode("const", "0x0", 1, constant=True)]},
        ],
    }]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 3
    assert 'rvi_call_x86_32(ctx, rvi_1_call_target_value, UINT32_C(0x401001), "ram")' in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; uint8_t ram[512]; unsigned userop_calls; unsigned function_calls; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(out, base + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(base + offset, in, size);
    return 0;
}
static int call_function(void *opaque, uint64_t target) {
    TestState *state = (TestState *)opaque;
    if (target != UINT64_C(0x1234)) return -1;
    state->function_calls++;
    return 0;
}
static int execute_userop(void *opaque, uint32_t index, const uint64_t *args,
                          const unsigned *sizes, size_t count, uint64_t *output, unsigned output_size) {
    TestState *state = (TestState *)opaque;
    if (index != 16 || count != 1 || args[0] != 0x1234 || sizes[0] != 4 || output_size != 4 || !output)
        return -1;
    state->userop_calls++;
    *output = args[0];
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {0};
    uint32_t esp = 0x200;
    memcpy(state.registers + 0x10, &esp, sizeof(esp));
    RviPcodeContext context = {&state, read_bytes, write_bytes, call_function, execute_userop};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t final_esp = 0;
    memcpy(&final_esp, state.registers + 0x10, sizeof(final_esp));
    return state.userop_calls == 1 && state.function_calls == 1 && final_esp == esp ? 0 : 2;
}
'''
    c_path = tmp_path / "computed-call-return.c"
    executable = tmp_path / "computed-call-return"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_emits_x87_wait_for_pcode_empty_x86_instruction(tmp_path: Path) -> None:
    if platform.machine().lower() not in {"x86_64", "amd64", "i386", "i486", "i586", "i686", "x86"}:
        pytest.skip("x87 WAIT runtime requires an x86 host")
    row = _function_row()
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "WAIT", "flow_type": "FALL_THROUGH", "flows": [], "pcode": []},
        {"address": "0x00401001", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    row["instruction_count"] = len(row["instructions"])
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 1
    assert "rvi_x87_wait()" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    RviPcodeContext context = {0};
    return rvi_00401000(&context) == 0 ? 0 : 1;
}
'''
    c_path = tmp_path / "x87-wait.c"
    executable = tmp_path / "x87-wait"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_executes_conditional_and_unconditional_intra_function_branches(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 5
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "JNZ", "flow_type": "CONDITIONAL_JUMP",
         "flows": ["0x00401008"], "pcode": [{
             "opcode": "CBRANCH", "output": None,
             "inputs": [_varnode("ram", "0x401008", 4), _varnode("register", "0x0", 1)],
         }]},
        {"address": "0x00401003", "mnemonic": "MOV", "flow_type": "FALL_THROUGH",
         "flows": [], "pcode": [{
             "opcode": "COPY", "output": _varnode("register", "0x4", 4),
             "inputs": [_varnode("const", "0x1", 4, constant=True)],
         }]},
        {"address": "0x00401006", "mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP",
         "flows": ["0x0040100b"], "pcode": [{
             "opcode": "BRANCH", "output": None,
             "inputs": [_varnode("ram", "0x40100b", 4)],
         }]},
        {"address": "0x00401008", "mnemonic": "MOV", "flow_type": "FALL_THROUGH",
         "flows": [], "pcode": [{
             "opcode": "COPY", "output": _varnode("register", "0x4", 4),
             "inputs": [_varnode("const", "0x2", 4, constant=True)],
         }]},
        {"address": "0x0040100b", "mnemonic": "RET", "flow_type": "TERMINATOR",
         "flows": [], "pcode": [{
             "opcode": "RETURN", "output": None,
             "inputs": [_varnode("register", "0x20", 4)],
         }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 5
    assert "goto rvi_label_0000000000401008" in source
    assert "goto rvi_label_000000000040100b" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
static int run_branch(uint8_t condition, uint32_t expected) {
    TestState state = {{0}};
    state.registers[0] = condition;
    RviPcodeContext context = {&state, read_bytes, write_bytes};
    if (rvi_00401000(&context) != 0) return 1;
    uint32_t actual = 0;
    memcpy(&actual, state.registers + 4, sizeof(actual));
    return actual == expected ? 0 : 2;
}
int main(void) {
    return run_branch(0, 1) || run_branch(1, 2);
}
'''
    c_path = tmp_path / "branch.c"
    executable = tmp_path / "branch"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_enters_function_address_when_body_starts_at_lower_address(tmp_path: Path) -> None:
    row = _function_row()
    row["requested"] = row["resolved_address"] = "0x00401010"
    row["function"] = {
        "address": "0x00401010", "name": "entry_after_thunk", "size": 21,
        "calling_convention": None,
    }
    row["instruction_count"] = 3
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "RET", "flow_type": "TERMINATOR",
         "flows": [], "pcode": [{
             "opcode": "RETURN", "output": None,
             "inputs": [_varnode("register", "0x284", 4)],
         }]},
        {"address": "0x00401010", "mnemonic": "MOV", "flow_type": "FALL_THROUGH",
         "flows": [], "pcode": [{
             "opcode": "COPY", "output": _varnode("register", "0x4", 4),
             "inputs": [_varnode("const", "0x1234", 4, constant=True)],
         }]},
        {"address": "0x00401015", "mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP",
         "flows": ["0x00401000"], "pcode": [{
             "opcode": "BRANCH", "output": None,
             "inputs": [_varnode("ram", "0x401000", 4)],
         }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 3
    entry_goto = "goto rvi_label_0000000000401010;"
    assert entry_goto in source
    assert source.index(entry_goto) < source.index("rvi_label_0000000000401000:")

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[0x300]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401010(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    RviPcodeContext context = {&state, read_bytes, write_bytes};
    if (rvi_00401010(&context) != 0) return 1;
    uint32_t ecx = 0;
    memcpy(&ecx, state.registers + 4, sizeof(ecx));
    return ecx == UINT32_C(0x1234) ? 0 : 2;
}
'''
    c_path = tmp_path / "entry-after-thunk.c"
    executable = tmp_path / "entry-after-thunk"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)],
                   check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_lowers_repeat_instruction_pcode_loop(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 2
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "REP", "flow_type": "FALL_THROUGH",
         "fallthrough": "0x00401010", "flows": [], "pcode": [
             {"opcode": "INT_EQUAL", "output": _varnode("unique", "0x100", 1),
              "inputs": [_varnode("register", "0x4", 4), _varnode("const", "0x0", 4, constant=True)]},
             {"opcode": "CBRANCH", "output": None,
              "inputs": [_varnode("ram", "0x401010", 4), _varnode("unique", "0x100", 1)]},
             {"opcode": "INT_SUB", "output": _varnode("register", "0x4", 4),
              "inputs": [_varnode("register", "0x4", 4), _varnode("const", "0x1", 4, constant=True)]},
             {"opcode": "BRANCH", "output": None, "inputs": [_varnode("ram", "0x401000", 4)]},
         ]},
        {"address": "0x00401010", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 5
    assert "goto rvi_label_0000000000401000" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    uint32_t count = 3;
    memcpy(state.registers + 4, &count, sizeof(count));
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    memcpy(&count, state.registers + 4, sizeof(count));
    return count == 0 ? 0 : 2;
}
'''
    c_path = tmp_path / "repeat.c"
    executable = tmp_path / "repeat"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_accepts_conditional_repeat_branch_to_current_instruction() -> None:
    row = _function_row()
    row["instruction_count"] = 2
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "CMPSB.REPE", "flow_type": "FALL_THROUGH",
         "fallthrough": "0x00401002", "flows": [], "pcode": [{
             "opcode": "CBRANCH", "output": None,
             "inputs": [_varnode("ram", "0x401000", 4), _varnode("register", "0x206", 1)],
         }]},
        {"address": "0x00401002", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 2
    assert "goto rvi_label_0000000000401000" in source

    row["instructions"][0]["pcode"][0]["inputs"][0]["offset"] = "0x401008"
    with pytest.raises(PcodeLoweringError, match="CBRANCH conflicts with machine fallthrough"):
        compile_function(row, _address_spaces())


def test_codegen_lowers_forward_and_backward_pcode_relative_branches(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 1
    row["instructions"] = [{
        "address": "0x00401000", "mnemonic": "LOOP", "flow_type": "TERMINATOR", "flows": [], "pcode": [
            {"opcode": "INT_EQUAL", "output": _varnode("unique", "0x100", 1),
             "inputs": [_varnode("register", "0x4", 4), _varnode("const", "0x0", 4, constant=True)]},
            {"opcode": "CBRANCH", "output": None,
             "inputs": [_varnode("const", "0x3", 4, constant=True), _varnode("unique", "0x100", 1)]},
            {"opcode": "INT_SUB", "output": _varnode("register", "0x4", 4),
             "inputs": [_varnode("register", "0x4", 4), _varnode("const", "0x1", 4, constant=True)]},
            {"opcode": "BRANCH", "output": None,
             "inputs": [_varnode("const", "0xfffffffd", 4, constant=True)]},
            {"opcode": "COPY", "output": _varnode("register", "0x8", 4),
             "inputs": [_varnode("const", "0x4d", 4, constant=True)]},
            {"opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)]},
        ],
    }]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 6
    assert "goto rvi_pcode_0000000000401000_4" in source
    assert "goto rvi_pcode_0000000000401000_0" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}};
    uint32_t count = 3;
    memcpy(state.registers + 4, &count, sizeof(count));
    RviPcodeContext context = {&state, read_bytes, write_bytes, NULL, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    memcpy(&count, state.registers + 4, sizeof(count));
    uint32_t result = 0;
    memcpy(&result, state.registers + 8, sizeof(result));
    return count == 0 && result == 77 ? 0 : 2;
}
'''
    c_path = tmp_path / "relative-branch.c"
    executable = tmp_path / "relative-branch"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_dispatches_direct_tail_jump_outside_the_function(tmp_path: Path) -> None:
    row = _function_row()
    row["instruction_count"] = 1
    row["instructions"] = [{
        "address": "0x00401000", "mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP",
        "flows": ["0x00402000"], "pcode": [{
            "opcode": "BRANCH", "output": None,
            "inputs": [_varnode("ram", "0x402000", 4)],
        }],
    }]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 1
    assert "rvi_call(ctx, UINT64_C(0x402000))" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
static int call_target(void *opaque, uint64_t target) {
    uint64_t *observed = (uint64_t *)opaque;
    *observed = target;
    return 0;
}
int rvi_00401000(RviPcodeContext *ctx);
int main(void) {
    uint64_t target = 0;
    RviPcodeContext context = {&target, NULL, NULL, call_target, NULL};
    if (rvi_00401000(&context) != 0) return 1;
    return target == UINT64_C(0x402000) ? 0 : 2;
}
'''
    c_path = tmp_path / "tail-jump.c"
    executable = tmp_path / "tail-jump"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_compacts_sparse_unique_space_without_losing_overlaps() -> None:
    row = _function_row()
    row["instruction_count"] = 5
    row["instructions"] = [
        {"address": "0x00401000", "mnemonic": "ADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "INT_ADD", "output": _varnode("unique", "0x100", 4),
            "inputs": [_varnode("const", "0x5", 4, constant=True), _varnode("const", "0x6", 4, constant=True)],
        }]},
        {"address": "0x00401004", "mnemonic": "ADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "INT_ADD", "output": _varnode("unique", "0x100000", 4),
            "inputs": [_varnode("const", "0x3", 4, constant=True), _varnode("const", "0x4", 4, constant=True)],
        }]},
        {"address": "0x00401008", "mnemonic": "ADD", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "INT_ADD", "output": _varnode("unique", "0x100002", 4),
            "inputs": [_varnode("unique", "0x100", 4), _varnode("unique", "0x100000", 4)],
        }]},
        {"address": "0x0040100c", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("unique", "0x100002", 4)],
        }]},
        {"address": "0x00401010", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 5
    assert "uint8_t _unique[10]" in source
    assert '"unique", UINT64_C(0x6), 4' in source


def test_codegen_dispatches_direct_and_indirect_calls(tmp_path: Path) -> None:
    row = _function_row()
    row["function"] = {**row["function"], "address": "0x00401200"}
    memory_id = _varnode("const", "0x1a1", 4, constant=True)
    esp = _varnode("register", "0x10", 4)

    def call_stack(return_address: int) -> list[dict]:
        return [
            {"opcode": "INT_SUB", "output": esp, "inputs": [esp, _varnode("const", "0x4", 4, constant=True)]},
            {"opcode": "STORE", "output": None, "inputs": [memory_id, esp, _varnode("const", hex(return_address), 4, constant=True)]},
        ]

    row["instruction_count"] = 4
    row["instructions"] = [
        {"address": "0x00401200", "mnemonic": "CALL", "flow_type": "UNCONDITIONAL_CALL",
         "fallthrough": "0x00401205",
         "flows": ["0x00405000"], "pcode": [*call_stack(0x00401205), {
             "opcode": "CALL", "output": None, "inputs": [_varnode("ram", "0x405000", 4)],
         }]},
        {"address": "0x00401205", "mnemonic": "CALL", "flow_type": "COMPUTED_CALL",
         "fallthrough": "0x00401207",
         "flows": [], "pcode": [*call_stack(0x00401207), {
             "opcode": "CALLIND", "output": None, "inputs": [_varnode("register", "0xc", 4)],
         }]},
        {"address": "0x00401207", "mnemonic": "MOV", "flow_type": "FALL_THROUGH",
         "flows": [], "pcode": [{
             "opcode": "COPY", "output": _varnode("register", "0x4", 4),
             "inputs": [_varnode("const", "0x3", 4, constant=True)],
         }]},
        {"address": "0x0040120a", "mnemonic": "RET", "flow_type": "TERMINATOR",
         "flows": [], "pcode": [{
             "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
         }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 8
    assert 'rvi_call_x86_32(ctx, UINT64_C(0x405000), UINT32_C(0x401205), "ram")' in source
    assert 'rvi_call_x86_32(ctx, rvi_5_call_target_value, UINT32_C(0x401207), "ram")' in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct { uint8_t registers[64]; uint8_t ram[512]; uint64_t targets[2]; int call_count; } TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(out, base + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    uint8_t *base = strcmp(space, "register") == 0 ? state->registers :
                    strcmp(space, "ram") == 0 ? state->ram : NULL;
    size_t limit = strcmp(space, "register") == 0 ? sizeof(state->registers) : sizeof(state->ram);
    if (!base || offset + size > limit) return -1;
    memcpy(base + offset, in, size);
    return 0;
}
static int call_target(void *opaque, uint64_t target) {
    TestState *state = (TestState *)opaque;
    if (state->call_count >= 2) return -1;
    state->targets[state->call_count++] = target;
    uint32_t esp = 0, return_address = 0;
    memcpy(&esp, state->registers + 0x10, sizeof(esp));
    if (esp != 0x1fc) return -1;
    if (esp > sizeof(state->ram) - sizeof(return_address)) return -1;
    memcpy(&return_address, state->ram + esp, sizeof(return_address));
    if ((target == UINT64_C(0x405000) && return_address != UINT32_C(0x401205)) ||
        (target == UINT64_C(0x406000) && return_address != UINT32_C(0x401207))) return -1;
    if (target == UINT64_C(0x405000)) {
        esp += 4; /* Guest RET consumes its synthetic return address. */
        memcpy(state->registers + 0x10, &esp, sizeof(esp));
    }
    return 0;
}
int rvi_00401200(RviPcodeContext *ctx);
int main(void) {
    TestState state = {{0}, {0}, {0}, 0};
    uint32_t indirect_target = 0x00406000;
    memcpy(state.registers + 0xc, &indirect_target, sizeof(indirect_target));
    uint32_t initial_esp = 0x200;
    memcpy(state.registers + 0x10, &initial_esp, sizeof(initial_esp));
    RviPcodeContext context = {&state, read_bytes, write_bytes, call_target, NULL};
    if (rvi_00401200(&context) != 0 || state.call_count != 2) return 1;
    if (state.targets[0] != 0x00405000 || state.targets[1] != 0x00406000) return 2;
    uint32_t final_esp = 0;
    memcpy(&final_esp, state.registers + 0x10, sizeof(final_esp));
    if (final_esp != initial_esp) return 3;
    uint32_t result = 0;
    memcpy(&result, state.registers + 4, sizeof(result));
    return result == 3 ? 0 : 4;
}
'''
    c_path = tmp_path / "calls.c"
    executable = tmp_path / "calls"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_codegen_dispatches_computed_jump_to_enumerated_targets(tmp_path: Path) -> None:
    row = _function_row()
    row["function"] = {**row["function"], "address": "0x00401300"}
    row["instruction_count"] = 6
    row["instructions"] = [
        {"address": "0x00401300", "mnemonic": "JMP", "flow_type": "COMPUTED_JUMP",
         "flows": ["0x00401308", "0x00401310"], "pcode": [{
             "opcode": "BRANCHIND", "output": None, "inputs": [_varnode("register", "0x0", 4)],
         }]},
        {"address": "0x00401308", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("const", "0x1", 4, constant=True)],
        }]},
        {"address": "0x0040130b", "mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP",
         "flows": ["0x00401318"], "pcode": [{
             "opcode": "BRANCH", "output": None, "inputs": [_varnode("ram", "0x401318", 4)],
         }]},
        {"address": "0x00401310", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [], "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x4", 4),
            "inputs": [_varnode("const", "0x2", 4, constant=True)],
        }]},
        {"address": "0x00401313", "mnemonic": "JMP", "flow_type": "UNCONDITIONAL_JUMP",
         "flows": ["0x00401318"], "pcode": [{
             "opcode": "BRANCH", "output": None, "inputs": [_varnode("ram", "0x401318", 4)],
         }]},
        {"address": "0x00401318", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [], "pcode": [{
            "opcode": "RETURN", "output": None, "inputs": [_varnode("register", "0x20", 4)],
        }]},
    ]
    source, operation_count = compile_function(row, _address_spaces())
    assert operation_count == 6
    assert "default:" in source

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    harness = r'''
typedef struct {
    uint8_t registers[64];
    uint32_t call_count;
    uint64_t last_target;
} TestState;
static int read_bytes(void *opaque, const char *space, uint64_t offset, size_t size, uint8_t *out) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(out, state->registers + offset, size);
    return 0;
}
static int write_bytes(void *opaque, const char *space, uint64_t offset, size_t size, const uint8_t *in) {
    TestState *state = (TestState *)opaque;
    if (strcmp(space, "register") != 0 || offset + size > sizeof(state->registers)) return -1;
    memcpy(state->registers + offset, in, size);
    return 0;
}
static int call_target(void *opaque, uint64_t target) {
    TestState *state = (TestState *)opaque;
    ++state->call_count;
    state->last_target = target;
    return 0;
}
int rvi_00401300(RviPcodeContext *ctx);
static int run_target(uint32_t target, uint32_t expected) {
    TestState state = {{0}};
    memcpy(state.registers, &target, sizeof(target));
    RviPcodeContext context = {&state, read_bytes, write_bytes, call_target};
    if (rvi_00401300(&context) != 0) return 1;
    if (state.call_count != 0) return 2;
    uint32_t actual = 0;
    memcpy(&actual, state.registers + 4, sizeof(actual));
    return actual == expected ? 0 : 3;
}
static int run_external_target(uint32_t target) {
    TestState state = {{0}};
    memcpy(state.registers, &target, sizeof(target));
    RviPcodeContext context = {&state, read_bytes, write_bytes, call_target};
    if (rvi_00401300(&context) != 0) return 1;
    return state.call_count == 1 && state.last_target == target ? 0 : 2;
}
int main(void) {
    return run_target(0x00401308, 1) || run_target(0x00401310, 2) ||
           run_external_target(0x00406000);
}
'''
    c_path = tmp_path / "computed-branch.c"
    executable = tmp_path / "computed-branch"
    c_path.write_text(source + "\n" + harness, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", str(c_path), "-lm", "-o", str(executable)], check=True, capture_output=True)
    subprocess.run([str(executable)], check=True)


def test_corpus_cli_hash_pins_source_and_compiles_selected_row(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl.gz"
    row = _function_row()
    with gzip.open(corpus, "wt", encoding="utf-8") as stream:
        stream.write(json.dumps(row) + "\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraFunctionInstructionCorpus/1",
        "program": "sample.exe",
        "language_id": "x86:LE:32:default",
        "exported_function_count": 1,
        "instruction_count": 5,
        "output_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    spaces_path = tmp_path / "spaces.json"
    spaces_path.write_text(json.dumps(_address_spaces()), encoding="utf-8")

    source, count = compile_from_corpus(corpus, manifest, spaces_path, "401000")

    assert count == 5
    assert "rvi_00401000" in source
    manifest.write_text(manifest.read_text().replace(hashlib.sha256(corpus.read_bytes()).hexdigest(), "0" * 64))
    with pytest.raises(ValueError, match="SHA-256"):
        compile_from_corpus(corpus, manifest, spaces_path, "0x00401000")
