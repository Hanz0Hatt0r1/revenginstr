import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Export High-P-code basic blocks, operation locations, and CFG edges. */
public class ExportFunctionPcodeCFG extends GhidraScript {
    private static final String FORMAT_V1 = "REVENGINSTR.GhidraFunctionPcodeCFG/1";
    private static final String FORMAT_V2 = "REVENGINSTR.GhidraFunctionPcodeCFG/2";
    private static final String FORMAT_V3 = "REVENGINSTR.GhidraFunctionPcodeCFG/3";
    private static final String FORMAT_V4 = "REVENGINSTR.GhidraFunctionPcodeCFG/4";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException(
                "Usage: ExportFunctionPcodeCFG.java <output.jsonl> <program-id> <function-entry> [entry ...]");
        }
        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        String programId = args[1];
        if (programId.isEmpty()) throw new IllegalArgumentException("program-id must not be empty");
        boolean sawMemoryMetadataFlag = false;
        boolean sawLogicalMemoryMetadataFlag = false;
        boolean sawPhysicalMemoryMetadataFlag = false;
        boolean includePhysicalMemoryMetadata = false;
        boolean includeIndirectEffectLinks = false;
        boolean skipMissingEntryBlocks = false;
        List<Function> functions = new ArrayList<>();
        Set<String> seenEntries = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            monitor.checkCancelled();
            String token = args[i].trim();
            if ("--memory-metadata".equals(token)) {
                if (sawLogicalMemoryMetadataFlag || sawPhysicalMemoryMetadataFlag) {
                    throw new IllegalArgumentException("Conflicting or duplicate memory metadata flag");
                }
                sawLogicalMemoryMetadataFlag = true;
                sawMemoryMetadataFlag = true;
                continue;
            }
            if ("--physical-memory-metadata".equals(token)) {
                if (sawPhysicalMemoryMetadataFlag || sawLogicalMemoryMetadataFlag) {
                    throw new IllegalArgumentException("Conflicting or duplicate memory metadata flag");
                }
                sawPhysicalMemoryMetadataFlag = true;
                sawMemoryMetadataFlag = true;
                includePhysicalMemoryMetadata = true;
                continue;
            }
            if ("--indirect-effect-links".equals(token)) {
                if (includeIndirectEffectLinks) {
                    throw new IllegalArgumentException("Duplicate indirect effect links flag");
                }
                includeIndirectEffectLinks = true;
                includePhysicalMemoryMetadata = true;
                sawMemoryMetadataFlag = true;
                continue;
            }
            if ("--skip-missing-entry-blocks".equals(token)) {
                if (skipMissingEntryBlocks) {
                    throw new IllegalArgumentException("Duplicate skip-missing-entry-blocks flag");
                }
                skipMissingEntryBlocks = true;
                continue;
            }
            if (token.startsWith("FUN_") || token.startsWith("fun_")) token = token.substring(4);
            if (token.startsWith("0x") || token.startsWith("0X")) token = token.substring(2);
            Address address = toAddr(Long.parseUnsignedLong(token, 16));
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) throw new IllegalArgumentException("Function entry not found: " + args[i]);
            if (!seenEntries.add(function.getEntryPoint().toString())) {
                throw new IllegalArgumentException("Duplicate function entry: " + args[i]);
            }
            functions.add(function);
        }
        if (functions.isEmpty()) throw new IllegalArgumentException("at least one function entry is required");
        boolean includeMemoryMetadata = sawMemoryMetadataFlag;
        if (skipMissingEntryBlocks && !includeMemoryMetadata) {
            throw new IllegalArgumentException("--skip-missing-entry-blocks requires a memory metadata flag");
        }

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.toggleCCode(false) || !decompiler.toggleSyntaxTree(true)) {
            throw new IllegalStateException("Could not configure P-code-only decompilation");
        }
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open program");
        List<String> skippedEntryBlocks = new ArrayList<>();
        int exportedFunctions = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (Function function : functions) {
                monitor.checkCancelled();
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
                    String detail = results == null ? "no result" : results.getErrorMessage();
                    throw new IllegalStateException("Decompile failed for " + function.getEntryPoint() + ": " + detail);
                }
                String json = functionJson(programId, function, results.getHighFunction(),
                    includeMemoryMetadata, includePhysicalMemoryMetadata, includeIndirectEffectLinks,
                    skipMissingEntryBlocks);
                if (json == null) {
                    skippedEntryBlocks.add(function.getEntryPoint().toString());
                    continue;
                }
                out.write(json);
                out.newLine();
                exportedFunctions++;
            }
        } finally {
            decompiler.dispose();
        }
        String exportedFormat = includeIndirectEffectLinks ? FORMAT_V4
            : includePhysicalMemoryMetadata ? FORMAT_V3
            : includeMemoryMetadata ? FORMAT_V2 : FORMAT_V1;
        println("GHIDRA_FUNCTION_PCODE_CFG_FORMAT=" + exportedFormat);
        println("GHIDRA_FUNCTION_PCODE_CFG_FUNCTIONS=" + functions.size());
        println("GHIDRA_FUNCTION_PCODE_CFG_EXPORTED_FUNCTIONS=" + exportedFunctions);
        println("GHIDRA_FUNCTION_PCODE_CFG_SKIPPED_FUNCTIONS=" + skippedEntryBlocks.size());
        for (String entry : skippedEntryBlocks) {
            println("GHIDRA_FUNCTION_PCODE_CFG_SKIPPED_ENTRY=" + entry + " reason=entry_block_not_found");
        }
        println("Ghidra function P-code CFG export -> " + output);
    }

    private String functionJson(
            String programId, Function function, HighFunction high,
            boolean includeMemoryMetadata, boolean includePhysicalMemoryMetadata,
            boolean includeIndirectEffectLinks,
            boolean skipMissingEntryBlocks) {
        List<PcodeBlockBasic> blocks = high.getBasicBlocks();
        IdentityHashMap<PcodeBlockBasic, Integer> indices = new IdentityHashMap<>();
        for (int i = 0; i < blocks.size(); i++) indices.put(blocks.get(i), i);
        int entryBlockIndex = -1;
        for (int i = 0; i < blocks.size(); i++) {
            if (blocks.get(i).getStart().equals(function.getEntryPoint())) {
                if (entryBlockIndex >= 0) throw new IllegalStateException("Multiple entry blocks for " + function.getEntryPoint());
                entryBlockIndex = i;
            }
        }
        if (includeMemoryMetadata && entryBlockIndex < 0) {
            if (skipMissingEntryBlocks) return null;
            throw new IllegalStateException("Entry block not found for " + function.getEntryPoint());
        }
        StringBuilder out = new StringBuilder(256).append("{\"format\":")
            .append(q(includeIndirectEffectLinks ? FORMAT_V4
                : includePhysicalMemoryMetadata ? FORMAT_V3 : includeMemoryMetadata ? FORMAT_V2 : FORMAT_V1))
            .append(",\"program_id\":").append(q(programId))
            .append(",\"function_entry\":").append(q(function.getEntryPoint().toString()))
            .append(includeMemoryMetadata ? ",\"entry_block_index\":" + entryBlockIndex : "")
            .append(",\"blocks\":[");
        for (int i = 0; i < blocks.size(); i++) {
            if (i > 0) out.append(',');
            PcodeBlockBasic block = blocks.get(i);
            out.append("{\"block_index\":").append(i)
                .append(",\"start_address\":").append(q(block.getStart().toString()))
                .append(",\"stop_address\":").append(q(block.getStop().toString()))
                .append(",\"operations\":[");
            boolean firstOperation = true;
            java.util.Iterator<PcodeOp> operations = block.getIterator();
            while (operations.hasNext()) {
                PcodeOp operation = operations.next();
                SequenceNumber sequence = operation.getSeqnum();
                if (!firstOperation) out.append(',');
                firstOperation = false;
                out.append("{\"address\":").append(q(sequence.getTarget().toString()))
                    .append(",\"time\":").append(sequence.getTime())
                    .append(",\"opcode\":").append(q(operation.getMnemonic()));
                if (includeMemoryMetadata) {
                    out.append(",\"memory_space\":").append(memorySpace(operation))
                        .append(",\"memory_width_bytes\":").append(memoryWidth(operation));
                    if (includePhysicalMemoryMetadata) {
                        out.append(",\"memory_physical_space\":").append(memoryPhysicalSpace(operation))
                            .append(",\"memory_pointer_width_bytes\":").append(memoryPointerWidth(operation));
                    }
                }
                if (includeIndirectEffectLinks) {
                    out.append(",\"indirect_effect_link\":")
                        .append(indirectEffectLink(operation, high));
                }
                out.append('}');
            }
            out.append("],\"successors\":[");
            TreeSet<Integer> successors = new TreeSet<>();
            for (int edge = 0; edge < block.getOutSize(); edge++) {
                Integer successor = indices.get(block.getOut(edge));
                if (successor == null) throw new IllegalStateException("CFG edge points outside basic block list");
                successors.add(successor);
            }
            boolean firstSuccessor = true;
            for (Integer successor : successors) {
                if (!firstSuccessor) out.append(',');
                firstSuccessor = false;
                out.append(successor);
            }
            out.append("]}");
        }
        return out.append("]}").toString();
    }

    private String indirectEffectLink(PcodeOp operation, HighFunction high) {
        if (operation.getOpcode() != PcodeOp.INDIRECT) return "null";
        PcodeOp source = null;
        if (operation.getNumInputs() >= 2) {
            Varnode reference = operation.getInput(1);
            if (reference != null && reference.isConstant()) {
                long offset = reference.getOffset();
                if (offset >= 0 && offset <= Integer.MAX_VALUE) {
                    source = high.getOpRef((int) offset);
                }
            }
        }
        if (source == null || source == operation || source.getSeqnum() == null) {
            return "{\"status\":\"unresolved\",\"source_address\":null,\"source_time\":null,\"source_opcode\":null}";
        }
        SequenceNumber sourceSequence = source.getSeqnum();
        return "{\"status\":\"resolved\",\"source_address\":" +
            q(sourceSequence.getTarget().toString()) + ",\"source_time\":" +
            sourceSequence.getTime() + ",\"source_opcode\":" + q(source.getMnemonic()) + "}";
    }

    private String memorySpace(PcodeOp operation) {
        AddressSpace space = memoryAddressSpace(operation);
        return space == null ? "null" : q(space.getName());
    }

    private String memoryPhysicalSpace(PcodeOp operation) {
        AddressSpace space = memoryAddressSpace(operation);
        if (space == null || space.getPhysicalSpace() == null) return "null";
        return q(space.getPhysicalSpace().getName());
    }

    private String memoryPointerWidth(PcodeOp operation) {
        AddressSpace space = memoryAddressSpace(operation);
        if (space == null || space.getPointerSize() < 1) return "null";
        return Integer.toString(space.getPointerSize());
    }

    private AddressSpace memoryAddressSpace(PcodeOp operation) {
        if (operation.getOpcode() != PcodeOp.LOAD && operation.getOpcode() != PcodeOp.STORE) return null;
        if (operation.getNumInputs() < 1) return null;
        Varnode spaceId = operation.getInput(0);
        if (spaceId == null || !spaceId.isConstant()) return null;
        long offset = spaceId.getOffset();
        if (offset < 0 || offset > Integer.MAX_VALUE) return null;
        try {
            return currentProgram.getAddressFactory().getAddressSpace((int) offset);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private String memoryWidth(PcodeOp operation) {
        Varnode value = null;
        if (operation.getOpcode() == PcodeOp.LOAD) value = operation.getOutput();
        else if (operation.getOpcode() == PcodeOp.STORE && operation.getNumInputs() >= 3) value = operation.getInput(2);
        return value == null || value.getSize() < 1 ? "null" : Integer.toString(value.getSize());
    }

    private static String q(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
