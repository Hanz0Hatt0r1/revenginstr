"""Deterministic project-neutral structural metrics from portable P-code."""
from __future__ import annotations

from collections import Counter
from typing import Any

from revenginstr.family.features import portable_pcode

COMPARE_OPS = {
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
    "INT_SLESS", "INT_SLESSEQUAL", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
    "FLOAT_LESS", "FLOAT_LESSEQUAL", "FLOAT_NAN",
}
ARITHMETIC_OPS = {
    "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
    "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_NEG", "FLOAT_ABS",
    "FLOAT_SQRT", "FLOAT_CEIL", "FLOAT_FLOOR", "FLOAT_ROUND",
}
BITWISE_OPS = {
    "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
    "BOOL_AND", "BOOL_OR", "BOOL_XOR", "BOOL_NEGATE",
}
CONVERSION_OPS = {
    "CAST", "INT_ZEXT", "INT_SEXT", "INT_2COMP", "INT_NEGATE",
    "FLOAT_INT2FLOAT", "FLOAT_FLOAT2FLOAT", "FLOAT_TRUNC",
}
POINTER_OPS = {"PTRADD", "PTRSUB"}
MEMORY_OPS = {"LOAD", "STORE"}
DIRECT_CALL_OPS = {"CALL"}
INDIRECT_CALL_OPS = {"CALLIND"}
CALL_OPS = DIRECT_CALL_OPS | INDIRECT_CALL_OPS
DIRECT_BRANCH_OPS = {"BRANCH"}
CONDITIONAL_BRANCH_OPS = {"CBRANCH"}
INDIRECT_BRANCH_OPS = {"BRANCHIND"}
BRANCH_OPS = DIRECT_BRANCH_OPS | CONDITIONAL_BRANCH_OPS | INDIRECT_BRANCH_OPS
RETURN_OPS = {"RETURN"}
CONTROL_FLOW_OPS = CALL_OPS | BRANCH_OPS | RETURN_OPS
SSA_MERGE_OPS = {"MULTIEQUAL"}
COPY_OPS = {"COPY"}
SLICE_OPS = {"PIECE", "SUBPIECE"}


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _portable_lines(text: str) -> list[str]:
    portable = portable_pcode(text)
    if not portable:
        portable = "\n".join(line for line in text.splitlines() if line.startswith("OP "))
    return [line.strip() for line in portable.splitlines() if line.strip()]


def _opcode(line: str) -> str:
    parts = line.split()
    if len(parts) < 2 or parts[0] != "OP":
        return "UNKNOWN"
    return parts[1]


def structural_metrics(text: str) -> dict[str, Any]:
    """Return name/address-free structural metrics for a portable P-code document."""
    lines = _portable_lines(text)
    opcodes = [_opcode(line) for line in lines]
    counts = Counter(opcodes)
    op_count = len(opcodes)

    load_count = counts["LOAD"]
    store_count = counts["STORE"]
    memory_count = sum(counts[op] for op in MEMORY_OPS)
    direct_call_count = sum(counts[op] for op in DIRECT_CALL_OPS)
    indirect_call_count = sum(counts[op] for op in INDIRECT_CALL_OPS)
    call_count = direct_call_count + indirect_call_count
    direct_branch_count = sum(counts[op] for op in DIRECT_BRANCH_OPS)
    conditional_branch_count = sum(counts[op] for op in CONDITIONAL_BRANCH_OPS)
    indirect_branch_count = sum(counts[op] for op in INDIRECT_BRANCH_OPS)
    branch_count = direct_branch_count + conditional_branch_count + indirect_branch_count
    return_count = sum(counts[op] for op in RETURN_OPS)
    control_flow_count = sum(counts[op] for op in CONTROL_FLOW_OPS)

    compare_count = sum(counts[op] for op in COMPARE_OPS)
    arithmetic_count = sum(counts[op] for op in ARITHMETIC_OPS)
    bitwise_count = sum(counts[op] for op in BITWISE_OPS)
    conversion_count = sum(counts[op] for op in CONVERSION_OPS)
    pointer_count = sum(counts[op] for op in POINTER_OPS)
    phi_count = sum(counts[op] for op in SSA_MERGE_OPS)
    copy_count = sum(counts[op] for op in COPY_OPS)
    slice_count = sum(counts[op] for op in SLICE_OPS)

    omitted_def_operand_count = sum(line.count("def:omitted") for line in lines)
    omitted_def_line_count = sum("def:omitted" in line for line in lines)
    unknown_opcode_count = counts["UNKNOWN"]
    decision_point_count = conditional_branch_count + indirect_branch_count
    cyclomatic_proxy = 1 + decision_point_count if op_count else 0

    return {
        "op_count": op_count,
        "unique_opcode_count": len(set(opcodes)),
        "unknown_opcode_count": unknown_opcode_count,
        "load_count": load_count,
        "store_count": store_count,
        "memory_op_count": memory_count,
        "memory_op_ratio": _ratio(memory_count, op_count),
        "direct_call_count": direct_call_count,
        "indirect_call_count": indirect_call_count,
        "call_count": call_count,
        "call_density": _ratio(call_count, op_count),
        "indirect_call_ratio": _ratio(indirect_call_count, call_count),
        "direct_branch_count": direct_branch_count,
        "conditional_branch_count": conditional_branch_count,
        "indirect_branch_count": indirect_branch_count,
        "branch_count": branch_count,
        "branch_density": _ratio(branch_count, op_count),
        "return_count": return_count,
        "control_flow_op_count": control_flow_count,
        "control_flow_density": _ratio(control_flow_count, op_count),
        "decision_point_count": decision_point_count,
        "cyclomatic_proxy": cyclomatic_proxy,
        "compare_count": compare_count,
        "arithmetic_count": arithmetic_count,
        "bitwise_count": bitwise_count,
        "conversion_count": conversion_count,
        "pointer_op_count": pointer_count,
        "phi_count": phi_count,
        "copy_count": copy_count,
        "slice_op_count": slice_count,
        "omitted_def_operand_count": omitted_def_operand_count,
        "omitted_def_line_count": omitted_def_line_count,
        "omitted_def_line_ratio": _ratio(omitted_def_line_count, op_count),
        "definition_coverage_proxy": 1.0 - _ratio(omitted_def_line_count, op_count) if op_count else 0.0,
    }
