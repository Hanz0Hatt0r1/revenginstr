# Ghidra function identity export

`ghidra/ExportGhidraFunctionIdentities.java` resolves requested addresses to
function identities and signatures without exporting bytes or decompiler text.
Its plan TSV has exactly `plan_id`, `requested_entry`, and `resolution`
(`exact` or `containing`) columns. Output rows follow
`schemas/ghidra-function-identities-v1.schema.json`.

Consumers assign opaque plan IDs and keep project-specific meaning in their
local plan and adapter.
