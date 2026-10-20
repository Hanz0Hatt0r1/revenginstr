# PointerProvenance/1

`revenginstr-pointer-provenance` follows exact P-code def-use tokens from
`GhidraFunctionPcodeFlow/1` TSV and emits one `PointerProvenance/1` JSONL row
for every operation with an output. If indirect-call evidence is supplied, it
also emits one row per exact `CALLIND` target. Each alternative records its
structural root, signed byte offset, value width, transformation path, source
hashes, and an explicit resolution or abstention status.

The analyzer never treats an unrooted register or arbitrary varnode as a formal
parameter. Optional caller-root TSVs (`GhidraCallerArgumentParameterRoot/1` or
`/2`) seed function-parameter facts only after an exact join on caller entry,
call address, callee entry, and callee parameter index. The v2 form preserves
its signed byte offset. Those root rows and P-code rows are both hash-pinned in
the output evidence.

Supported value flow is deliberately small:

- `COPY` and same-width `CAST` preserve a known root;
- `PTRADD`, `PTRSUB`, `INT_ADD`, and `INT_SUB` propagate only constant byte
  offsets with matching pointer widths. `PTRSUB` adds its byte offset to the
  base pointer; `INT_SUB` subtracts its right operand;
- `MULTIEQUAL` retains bounded, distinct root/offset alternatives;
- `LOAD` creates a memory-read anchor and separately records the address
  expression. It does not claim which value was stored there;
- `INDIRECT`, calls, unsupported operations, dynamic offsets, cycles, depth
  exhaustion, overflow, and width mismatches remain visible abstentions.

Run it with one or more flow TSVs:

```sh
revenginstr-pointer-provenance \
  --program-id 'consumer:analysis-id' \
  --pcode-flow flow.tsv \
  --parameter-roots parameter-offset-roots.tsv \
  --indirect-call-evidence callind.jsonl \
  --output pointer-provenance.jsonl
```

Repeat `--pcode-flow` and `--indirect-call-evidence` for additional files from
one analyzed program. The flow TSV has no program id, so `--program-id` is a
caller-supplied provenance label. An indirect target token is joined to its
exact `CALLIND` by function entry, call address, and call time, then to its
definition by opcode, address, time, and width. Caller-root rows join on exact
caller entry, call address, callee entry, and callee parameter index.
`--max-depth`, `--max-alternatives`, and `--max-operations` are finite work
budgets. Duplicate operations, malformed tokens, contradictory widths, or
ambiguous caller-site matches fail closed or produce an explicit abstention.

This artifact reports structural provenance only. A resolved parameter root or
memory-read anchor is not a class, object identity, vtable, runtime reaching
definition, or proof that a `CALLIND` is virtual. Consumers must validate new
structural coverage separately from class/vtable correctness.
