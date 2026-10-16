import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Export conservative High-P-code type evidence for the receiver (first call
 * argument) of CALLIND sites. Evidence only: no class/target inference and no
 * decompiler-C text. Transparent COPY/CAST/INDIRECT/MULTIEQUAL flow is bounded;
 * pointer arithmetic is deliberately not traversed.
 */
public class ExportIndirectCallReceiverTypes extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraIndirectReceiverType/1";
    private static final int MAX_FLOW_DEPTH = 4;
    private static final int MAX_FLOW_NODES = 16;

    private static class PlanRow {
        final String sourceId;
        final String sourceEntry;
        final int expectedCalls;
        PlanRow(String sourceId, String sourceEntry, int expectedCalls) {
            this.sourceId = sourceId;
            this.sourceEntry = sourceEntry;
            this.expectedCalls = expectedCalls;
        }
    }

    private static class TypeInfo {
        final DataType type;
        final int pointerDepth;
        final DataType pointee;
        TypeInfo(DataType type, int pointerDepth, DataType pointee) {
            this.type = type;
            this.pointerDepth = pointerDepth;
            this.pointee = pointee;
        }
    }

    private String cell(Object value) {
        if (value == null) return "-";
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String storageKind(Varnode node) {
        if (node == null) return "missing";
        if (node.isConstant()) return "constant";
        if (node.isRegister()) return "register";
        if (node.isUnique()) return "unique";
        if (node.isAddress()) return "address";
        return "other";
    }

    private String nodeToken(Varnode node) {
        if (node == null) return "-";
        if (node.isConstant()) return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        PcodeOp def = node.getDef();
        if (def != null) {
            SequenceNumber seq = def.getSeqnum();
            return "def:" + def.getMnemonic() + "@" + cell(seq.getTarget()) + ":" + seq.getTime() + ":" + node.getSize();
        }
        return storageKind(node) + ":" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private DataType unwrapTypedef(DataType type) {
        if (type instanceof TypeDef) return ((TypeDef) type).getBaseDataType();
        return type;
    }

    private TypeInfo inspectType(DataType original) {
        DataType type = unwrapTypedef(original);
        int pointerDepth = 0;
        DataType pointee = null;
        DataType cursor = type;
        while (cursor instanceof Pointer) {
            pointerDepth++;
            DataType next = unwrapTypedef(((Pointer) cursor).getDataType());
            if (pointerDepth == 1) pointee = next;
            if (next == null || next == cursor) break;
            cursor = next;
        }
        return new TypeInfo(type, pointerDepth, pointee);
    }

    private void collectTransparentTypeEvidence(Varnode node, int depth, Set<Varnode> seen,
            List<DataType> types) {
        if (node == null || depth > MAX_FLOW_DEPTH || seen.size() >= MAX_FLOW_NODES || !seen.add(node)) return;
        HighVariable high = node.getHigh();
        if (high != null && high.getDataType() != null) types.add(high.getDataType());
        PcodeOp def = node.getDef();
        if (def == null || depth == MAX_FLOW_DEPTH) return;
        int opcode = def.getOpcode();
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INDIRECT) {
            if (def.getNumInputs() >= 1) collectTransparentTypeEvidence(def.getInput(0), depth + 1, seen, types);
        } else if (opcode == PcodeOp.MULTIEQUAL) {
            for (int i = 0; i < def.getNumInputs(); i++)
                collectTransparentTypeEvidence(def.getInput(i), depth + 1, seen, types);
        }
    }

    private String jsonString(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '\"') out.append('\\').append(c);
            else if (c == '\n') out.append("\\n");
            else if (c == '\r') out.append("\\r");
            else if (c == '\t') out.append("\\t");
            else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('\"').toString();
    }

    private String jsonArray(Set<String> values) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) out.append(',');
            first = false;
            out.append(jsonString(value));
        }
        return out.append(']').toString();
    }

    private Function resolveFunction(String token) throws Exception {
        Address address = toAddr(token);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) throw new IllegalArgumentException("Function not found: " + token);
        return function;
    }

    private List<PlanRow> readPlan(File path) throws Exception {
        List<PlanRow> rows = new ArrayList<PlanRow>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            boolean first = true;
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] cols = line.split("\\t", -1);
                if (first && cols.length >= 2 && "source_id".equals(cols[0])) {
                    first = false;
                    continue;
                }
                first = false;
                if (cols.length < 2) throw new IllegalArgumentException("Invalid plan row: " + line);
                int expectedCalls = cols.length >= 3 && !cols[2].isEmpty() ? Integer.parseInt(cols[2]) : -1;
                rows.add(new PlanRow(cols[0], cols[1], expectedCalls));
            }
        }
        return rows;
    }

    private void writeHeader(BufferedWriter out) throws Exception {
        out.write("format\tsource_id\tfunction_entry\tcall_index\tcall_address\tcall_time\targ_count\t" +
            "receiver_present\treceiver_storage_kind\treceiver_token\treceiver_type_name\t" +
            "receiver_type_display\treceiver_pointer_depth\tpointee_type_name\tpointee_type_display\t" +
            "flow_type_node_count\tflow_single_pointer_pointee_names_json\t" +
            "flow_single_pointer_pointee_displays_json");
        out.newLine();
    }

    private void writeCall(BufferedWriter out, String sourceId, Function function, int callIndex,
            PcodeOpAST op) throws Exception {
        SequenceNumber seq = op.getSeqnum();
        int argCount = Math.max(0, op.getNumInputs() - 1);
        Varnode receiver = op.getNumInputs() >= 2 ? op.getInput(1) : null;
        HighVariable high = receiver == null ? null : receiver.getHigh();
        DataType originalType = high == null ? null : high.getDataType();
        TypeInfo direct = inspectType(originalType);
        List<DataType> flowTypes = new ArrayList<DataType>();
        collectTransparentTypeEvidence(receiver, 0, new HashSet<Varnode>(), flowTypes);
        LinkedHashSet<String> flowNames = new LinkedHashSet<String>();
        LinkedHashSet<String> flowDisplays = new LinkedHashSet<String>();
        for (DataType candidate : flowTypes) {
            TypeInfo info = inspectType(candidate);
            if (info.pointerDepth != 1 || info.pointee == null) continue;
            String name = info.pointee.getName();
            String display = info.pointee.getDisplayName();
            if (name != null && !name.isEmpty()) flowNames.add(name);
            if (display != null && !display.isEmpty()) flowDisplays.add(display);
        }
        out.write(FORMAT + "\t" + cell(sourceId) + "\t" + cell(function.getEntryPoint()) + "\t" +
            callIndex + "\t" + cell(seq.getTarget()) + "\t" + seq.getTime() + "\t" + argCount + "\t" +
            (receiver == null ? 0 : 1) + "\t" + storageKind(receiver) + "\t" + nodeToken(receiver) + "\t" +
            cell(originalType == null ? null : originalType.getName()) + "\t" +
            cell(originalType == null ? null : originalType.getDisplayName()) + "\t" + direct.pointerDepth + "\t" +
            cell(direct.pointee == null ? null : direct.pointee.getName()) + "\t" +
            cell(direct.pointee == null ? null : direct.pointee.getDisplayName()) + "\t" +
            flowTypes.size() + "\t" + jsonArray(flowNames) + "\t" + jsonArray(flowDisplays));
        out.newLine();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Usage: ExportIndirectCallReceiverTypes.java <plan.tsv> <output.tsv>");
        File planPath = new File(args[0]);
        File outputPath = new File(args[1]);
        File parent = outputPath.getParentFile();
        if (parent != null) parent.mkdirs();
        List<PlanRow> plan = readPlan(planPath);

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open current program in decompiler");
        int functionsOk = 0, functionsFailed = 0, calls = 0, expectedMismatches = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8))) {
            writeHeader(out);
            for (PlanRow item : plan) {
                if (monitor.isCancelled()) break;
                Function function;
                try {
                    function = resolveFunction(item.sourceEntry);
                } catch (Exception error) {
                    printerr("RECEIVER_TYPE_FUNCTION_NOT_FOUND source=" + item.sourceId + " entry=" + item.sourceEntry);
                    functionsFailed++;
                    continue;
                }
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
                    String message = results == null ? "no result" : results.getErrorMessage();
                    printerr("RECEIVER_TYPE_DECOMPILE_FAILED source=" + item.sourceId + " message=" + cell(message));
                    functionsFailed++;
                    continue;
                }
                HighFunction high = results.getHighFunction();
                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                int callIndex = 0;
                while (operations.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST op = operations.next();
                    if (op.getOpcode() != PcodeOp.CALLIND || op.getNumInputs() < 1) continue;
                    writeCall(out, item.sourceId, function, callIndex, op);
                    callIndex++;
                    calls++;
                }
                if (item.expectedCalls >= 0 && item.expectedCalls != callIndex) {
                    expectedMismatches++;
                    printerr("RECEIVER_TYPE_CALL_COUNT_MISMATCH source=" + item.sourceId + " expected=" + item.expectedCalls + " actual=" + callIndex);
                }
                functionsOk++;
            }
        } finally {
            decompiler.dispose();
        }
        println("RECEIVER_TYPE_FORMAT=" + FORMAT);
        println("RECEIVER_TYPE_PLAN_FUNCTIONS=" + plan.size());
        println("RECEIVER_TYPE_FUNCTIONS_OK=" + functionsOk);
        println("RECEIVER_TYPE_FUNCTIONS_FAILED=" + functionsFailed);
        println("RECEIVER_TYPE_CALLS=" + calls);
        println("RECEIVER_TYPE_EXPECTED_CALL_MISMATCHES=" + expectedMismatches);
        println("RECEIVER_TYPE_OUTPUT=" + outputPath.getAbsolutePath());
    }
}
