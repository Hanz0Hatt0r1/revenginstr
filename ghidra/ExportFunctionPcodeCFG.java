import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;

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
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionPcodeCFG/1";

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
        List<Function> functions = new ArrayList<>();
        Set<String> seenEntries = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            monitor.checkCancelled();
            String token = args[i].trim();
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

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open program");
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (Function function : functions) {
                monitor.checkCancelled();
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
                    String detail = results == null ? "no result" : results.getErrorMessage();
                    throw new IllegalStateException("Decompile failed for " + function.getEntryPoint() + ": " + detail);
                }
                out.write(functionJson(programId, function, results.getHighFunction()));
                out.newLine();
            }
        } finally {
            decompiler.dispose();
        }
        println("Ghidra function P-code CFG export -> " + output);
    }

    private String functionJson(String programId, Function function, HighFunction high) {
        List<PcodeBlockBasic> blocks = high.getBasicBlocks();
        IdentityHashMap<PcodeBlockBasic, Integer> indices = new IdentityHashMap<>();
        for (int i = 0; i < blocks.size(); i++) indices.put(blocks.get(i), i);
        StringBuilder out = new StringBuilder(256).append("{\"format\":").append(q(FORMAT))
            .append(",\"program_id\":").append(q(programId))
            .append(",\"function_entry\":").append(q(function.getEntryPoint().toString()))
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
                    .append(",\"opcode\":").append(q(operation.getMnemonic())).append('}');
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
