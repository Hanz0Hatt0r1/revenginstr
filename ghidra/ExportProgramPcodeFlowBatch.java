import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/** Bounded, read-only batch export of exact High-P-code flows and CALLIND expressions. */
public class ExportProgramPcodeFlowBatch extends GhidraScript {
    private static final String FLOW_HEADER =
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name";
    private static final String EVIDENCE_FORMAT = "REVENGINSTR.GhidraIndirectCallEvidence/4";
    private static final String ACQUISITION_FORMAT = "REVENGINSTR.GhidraPcodeFlowAcquisition/1";
    private static final int DEFAULT_MAX_FUNCTIONS = 1000;
    private static final int DEFAULT_MAX_TOTAL_SECONDS = 3600;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final int MAX_EXPRESSION_DEPTH = 6;

    private static final class TargetResolution {
        final String status;
        final Address slot;
        final Address functionEntry;

        TargetResolution(String status, Address slot, Address functionEntry) {
            this.status = status;
            this.slot = slot;
            this.functionEntry = functionEntry;
        }
    }

    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String json(String value) {
        if (value == null) return "null";
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

    private String address(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
    }

    private String nodeToken(Varnode node) {
        if (node == null) return "none";
        if (node.isConstant()) {
            return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        }
        PcodeOp definition = node.getDef();
        if (definition != null) {
            SequenceNumber sequence = definition.getSeqnum();
            return "def:" + definition.getMnemonic() + "@" + cell(sequence.getTarget()) + ":" +
                sequence.getTime() + ":" + node.getSize();
        }
        if (node.isRegister()) return "register:" + cell(node.getAddress()) + ":" + node.getSize();
        if (node.isUnique()) return "unique:" + cell(node.getAddress()) + ":" + node.getSize();
        if (node.isAddress()) return "address:" + cell(node.getAddress()) + ":" + node.getSize();
        return "input:" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private String flowToken(Varnode node) {
        if (node == null) return "-";
        if (node.isConstant()) {
            return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        }
        PcodeOp definition = node.getDef();
        if (definition != null) {
            SequenceNumber sequence = definition.getSeqnum();
            return "def:" + cell(sequence.getTarget()) + ":" + sequence.getTime() + ":" + node.getSize();
        }
        String kind = node.isRegister() ? "register" : node.isUnique() ? "unique" :
            node.isAddress() ? "address" : "input";
        return kind + ":" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private String expression(Varnode node, int depth, Set<String> seen) {
        if (node == null) return "none";
        String token = nodeToken(node);
        if (depth >= MAX_EXPRESSION_DEPTH) return token + "{depth-limit}";
        if (!seen.add(token)) return token + "{cycle}";
        PcodeOp definition = node.getDef();
        if (definition == null) return token;

        int opcode = definition.getOpcode();
        StringBuilder out = new StringBuilder(definition.getMnemonic()).append('(');
        int start = opcode == PcodeOp.LOAD ? Math.min(1, definition.getNumInputs()) : 0;
        if (opcode == PcodeOp.INDIRECT) {
            int count = Math.min(1, definition.getNumInputs());
            for (int i = 0; i < count; i++) {
                if (i > 0) out.append(',');
                out.append(expression(definition.getInput(i), depth + 1, new HashSet<String>(seen)));
            }
            return out.append(')').toString();
        }
        for (int i = start; i < definition.getNumInputs(); i++) {
            if (i > start) out.append(',');
            out.append(expression(definition.getInput(i), depth + 1, new HashSet<String>(seen)));
        }
        return out.append(')').toString();
    }

    private Address callTargetAddress(PcodeOpAST op) {
        if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 1) return null;
        Varnode target = op.getInput(0);
        if (target == null) return null;
        if (!target.isConstant()) return target.getAddress();
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset());
        } catch (Exception ignored) {
            return null;
        }
    }

    private Function resolveCallTarget(PcodeOpAST op) {
        Address target = callTargetAddress(op);
        if (target == null) return null;
        Function function = currentProgram.getFunctionManager().getFunctionAt(target);
        if (function != null) return function;
        long offset = target.getOffset();
        if ((offset & 1L) != 0L) {
            try {
                Address normalized = target.getAddressSpace().getAddress(offset & ~1L);
                return currentProgram.getFunctionManager().getFunctionAt(normalized);
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private String dataInputs(PcodeOpAST op) {
        int start = (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) ? 1 : 0;
        StringBuilder inputs = new StringBuilder();
        for (int index = start; index < op.getNumInputs(); index++) {
            if (inputs.length() > 0) inputs.append(';');
            inputs.append(flowToken(op.getInput(index)));
        }
        return inputs.length() == 0 ? "-" : inputs.toString();
    }

    private List<String> readRequests(String path, int maxFunctions) throws Exception {
        List<String> requests = new ArrayList<String>();
        Set<String> unique = new HashSet<String>();
        for (String raw : Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8)) {
            String request = raw.trim();
            if (request.isEmpty() || request.startsWith("#")) continue;
            if (!unique.add(request)) throw new IllegalArgumentException("duplicate function request: " + request);
            requests.add(request);
            if (requests.size() > maxFunctions) {
                throw new IllegalArgumentException("function list exceeds max-functions=" + maxFunctions);
            }
        }
        if (requests.isEmpty()) throw new IllegalArgumentException("function list is empty");
        return requests;
    }

    private Function resolveExactFunction(String request) throws Exception {
        Address address = toAddr(request);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) throw new IllegalArgumentException("function not found at exact entry: " + request);
        return function;
    }

    private void writeFlow(BufferedWriter out, Function function, PcodeOpAST op) throws Exception {
        SequenceNumber sequence = op.getSeqnum();
        Function callee = resolveCallTarget(op);
        String calleeEntry = callee == null ? "-" : cell(callee.getEntryPoint());
        String calleeName = callee == null ? "-" : cell(callee.getName(true));
        out.write(cell(function.getEntryPoint()) + "\t" + cell(sequence.getTarget()) + "\t" +
            sequence.getTime() + "\t" + cell(op.getMnemonic()) + "\t" + flowToken(op.getOutput()) + "\t" +
            dataInputs(op) + "\t" + calleeEntry + "\t" + calleeName);
        out.newLine();
    }

    private void writeEvidence(BufferedWriter out, String requested, Function function,
            PcodeOpAST op, HighFunction high) throws Exception {
        SequenceNumber sequence = op.getSeqnum();
        Varnode target = op.getNumInputs() > 0 ? op.getInput(0) : null;
        TargetResolution resolution = resolveTarget(target, 0);
        out.write("{\"format\":" + json(EVIDENCE_FORMAT) +
            ",\"program\":" + json(currentProgram.getName()) +
            ",\"program_sha256\":" + json(currentProgram.getExecutableSHA256()) +
            ",\"architecture\":{\"language_id\":" + json(currentProgram.getLanguageID().toString()) +
            ",\"pointer_width_bytes\":" + currentProgram.getDefaultPointerSize() +
            ",\"endianness\":" + json(currentProgram.getLanguage().isBigEndian() ? "big" : "little") + "}" +
            ",\"requested\":" + json(requested) +
            ",\"function_entry\":" + json(address(function.getEntryPoint())) +
            ",\"call_address\":" + json(address(sequence.getTarget())) +
            ",\"call_time\":" + sequence.getTime() +
            ",\"target\":" + json(nodeToken(target)) +
            ",\"target_expression\":" + json(expression(target, 0, new HashSet<String>())) +
            ",\"target_resolution\":" + targetResolutionJson(resolution) +
            ",\"parameter_roots\":" + parameterRootsJson(high, op, resolution.functionEntry != null) +
            ",\"arg_count\":" + Math.max(0, op.getNumInputs() - 1) + "}");
        out.newLine();
    }

    private String parameterRootsJson(HighFunction high, PcodeOp op, boolean targetResolved) {
        if (!targetResolved) return "[]";
        StringBuilder roots = new StringBuilder("[");
        for (int argumentIndex = 0; argumentIndex + 1 < op.getNumInputs(); argumentIndex++) {
            Varnode argument = op.getInput(argumentIndex + 1);
            if (argument == null || argument.getDef() != null) continue;
            int callerParameterIndex = parameterIndex(high, argument);
            if (callerParameterIndex < 0) continue;
            if (roots.length() > 1) roots.append(',');
            roots.append("{\"parameter_index\":").append(argumentIndex)
                .append(",\"caller_parameter_index\":").append(callerParameterIndex)
                .append(",\"argument_token\":").append(json(nodeToken(argument))).append('}');
        }
        return roots.append(']').toString();
    }

    private int parameterIndex(HighFunction high, Varnode node) {
        if (high == null || node == null || node.getHigh() == null) return -1;
        LocalSymbolMap map = high.getLocalSymbolMap();
        if (map == null) return -1;
        HighVariable target = node.getHigh();
        for (int index = 0; index < map.getNumParams(); index++) {
            HighSymbol symbol = map.getParamSymbol(index);
            if (symbol == null || symbol.getHighVariable() == null) continue;
            HighVariable parameter = symbol.getHighVariable();
            if (parameter == target) return index;
            if (parameter.getRepresentative() != null && target.getRepresentative() != null &&
                    parameter.getRepresentative().equals(target.getRepresentative())) return index;
        }
        return -1;
    }

    private String targetResolutionJson(TargetResolution resolution) {
        return "{\"status\":" + json(resolution.status) +
            ",\"slot_address\":" + json(resolution.slot == null ? null : address(resolution.slot)) +
            ",\"function_entry\":" + json(resolution.functionEntry == null ? null : address(resolution.functionEntry)) + "}";
    }

    private TargetResolution resolveTarget(Varnode value, int depth) {
        if (value == null || depth > MAX_EXPRESSION_DEPTH) return unresolved("unsupported_target_expression", null);
        if (value.isAddress()) {
            return depth == 0
                ? unresolved("unsupported_target_expression", null)
                : resolveFunctionPointer(value.getAddress());
        }
        if (value.isConstant()) {
            return resolveFunctionAt(addressFromOffset(value.getOffset()), "resolved_constant_function", null);
        }
        PcodeOp definition = value.getDef();
        if (definition == null) return unresolved("unsupported_target_expression", null);
        int opcode = definition.getOpcode();
        if ((opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) && definition.getNumInputs() == 1) {
            return resolveTarget(definition.getInput(0), depth + 1);
        }
        Address slot = null;
        if (opcode == PcodeOp.INDIRECT && definition.getNumInputs() >= 1) {
            slot = staticAddress(definition.getInput(0));
        } else if (opcode == PcodeOp.LOAD && definition.getNumInputs() >= 2) {
            slot = staticAddress(definition.getInput(1));
        }
        if (slot == null) return unresolved("unsupported_target_expression", null);
        return resolveFunctionPointer(slot);
    }

    private TargetResolution resolveFunctionPointer(Address slot) {
        int width = currentProgram.getDefaultPointerSize();
        if (width != 4 && width != 8) return unresolved("unreadable_pointer", slot);
        Memory memory = currentProgram.getMemory();
        byte[] bytes = new byte[width];
        try {
            if (!memory.contains(slot) || memory.getBytes(slot, bytes) != width) {
                return unresolved("unreadable_pointer", slot);
            }
        } catch (Exception ignored) {
            return unresolved("unreadable_pointer", slot);
        }
        BigInteger pointer = BigInteger.ZERO;
        if (currentProgram.getLanguage().isBigEndian()) {
            for (byte b : bytes) pointer = pointer.shiftLeft(8).or(BigInteger.valueOf(b & 0xff));
        } else {
            for (int i = bytes.length - 1; i >= 0; i--) {
                pointer = pointer.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xff));
            }
        }
        if (pointer.signum() == 0 || pointer.bitLength() > 64) {
            return unresolved("non_function_target", slot);
        }
        return resolveFunctionAt(addressFromOffset(pointer.longValue()), "resolved_static_function_pointer", slot);
    }

    private Address staticAddress(Varnode value) {
        if (value == null) return null;
        if (value.isAddress()) return value.getAddress();
        if (value.isConstant()) return addressFromOffset(value.getOffset());
        return null;
    }

    private Address addressFromOffset(long offset) {
        try {
            AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            return space.getAddress(offset);
        } catch (Exception ignored) {
            return null;
        }
    }

    private TargetResolution resolveFunctionAt(Address target, String status, Address slot) {
        if (target == null) return unresolved("non_function_target", slot);
        Function function = currentProgram.getFunctionManager().getFunctionAt(target);
        if (function == null) return unresolved("non_function_target", slot);
        return new TargetResolution(status, slot, function.getEntryPoint());
    }

    private TargetResolution unresolved(String status, Address slot) {
        return new TargetResolution(status, slot, null);
    }

    private void writeAcquisition(BufferedWriter out, Function function, String state,
            int operationCount, int callindCount, String error) throws Exception {
        out.write("{\"format\":" + json(ACQUISITION_FORMAT) +
            ",\"program\":" + json(currentProgram.getName()) +
            ",\"function_entry\":" + json(cell(function.getEntryPoint())) +
            ",\"state\":" + json(state) +
            ",\"operation_count\":" + operationCount +
            ",\"callind_count\":" + callindCount +
            ",\"error\":" + json(error) + "}");
        out.newLine();
    }

    @Override
    public void run() throws Exception {
        String executableSha256 = currentProgram.getExecutableSHA256();
        if (executableSha256 == null || !executableSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalStateException("Current program has no valid executable SHA-256");
        }
        String[] args = getScriptArgs();
        if (args.length < 4 || args.length > 6) {
            throw new IllegalArgumentException(
                "Usage: ExportProgramPcodeFlowBatch.java <function-list.txt> <flow.tsv> " +
                "<callind.jsonl> <acquisition.jsonl> [max-functions] [max-total-seconds]");
        }
        int maxFunctions = args.length == 5 ? Integer.parseInt(args[4]) : DEFAULT_MAX_FUNCTIONS;
        if (maxFunctions < 1) throw new IllegalArgumentException("max-functions must be >= 1");
        int maxTotalSeconds = args.length == 6 ? Integer.parseInt(args[5]) : DEFAULT_MAX_TOTAL_SECONDS;
        if (maxTotalSeconds < 1) throw new IllegalArgumentException("max-total-seconds must be >= 1");
        List<String> requests = readRequests(args[0], maxFunctions);
        File flowFile = new File(args[1]).getAbsoluteFile();
        File evidenceFile = new File(args[2]).getAbsoluteFile();
        File acquisitionFile = new File(args[3]).getAbsoluteFile();
        for (File output : new File[] {flowFile, evidenceFile, acquisitionFile}) {
            File parent = output.getParentFile();
            if (parent != null) parent.mkdirs();
        }

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open current program in decompiler");
        }
        int totalFlowRows = 0;
        int complete = 0;
        int noPcode = 0;
        int failed = 0;
        long startedAt = System.nanoTime();
        try (BufferedWriter flow = new BufferedWriter(new OutputStreamWriter(
                 new FileOutputStream(flowFile), StandardCharsets.UTF_8));
             BufferedWriter evidence = new BufferedWriter(new OutputStreamWriter(
                 new FileOutputStream(evidenceFile), StandardCharsets.UTF_8));
             BufferedWriter acquisition = new BufferedWriter(new OutputStreamWriter(
                 new FileOutputStream(acquisitionFile), StandardCharsets.UTF_8))) {
            flow.write(FLOW_HEADER);
            flow.newLine();
            for (String request : requests) {
                if (monitor.isCancelled()) throw new IllegalStateException("cancelled before batch completion");
                long elapsedSeconds = (System.nanoTime() - startedAt) / 1_000_000_000L;
                if (elapsedSeconds >= maxTotalSeconds) {
                    throw new IllegalStateException("batch exceeded max-total-seconds=" + maxTotalSeconds);
                }
                Function function = resolveExactFunction(request);
                if (function.isExternal()) {
                    writeAcquisition(acquisition, function, "no_pcode", 0, 0, "external function");
                    noPcode++;
                    continue;
                }
                DecompileResults results;
                try {
                    results = decompiler.decompileFunction(
                        function, DECOMPILE_TIMEOUT_SECONDS, monitor);
                } catch (Exception error) {
                    writeAcquisition(acquisition, function, "decompile_failed", 0, 0, error.toString());
                    failed++;
                    continue;
                }
                HighFunction high = results == null ? null : results.getHighFunction();
                if (results == null || !results.decompileCompleted() || high == null) {
                    String message = results == null ? "no decompiler result" : results.getErrorMessage();
                    writeAcquisition(acquisition, function, "decompile_failed", 0, 0, message);
                    failed++;
                    continue;
                }
                int operationCount = 0;
                int callindCount = 0;
                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                while (operations.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST op = operations.next();
                    writeFlow(flow, function, op);
                    operationCount++;
                    if (op.getOpcode() == PcodeOp.CALLIND) {
                        callindCount++;
                        if (op.getNumInputs() > 0) writeEvidence(evidence, request, function, op, high);
                    }
                }
                if (monitor.isCancelled()) throw new IllegalStateException("cancelled during function export");
                if (operationCount == 0) {
                    writeAcquisition(acquisition, function, "no_pcode", 0, 0, null);
                    noPcode++;
                } else {
                    writeAcquisition(acquisition, function, "complete", operationCount, callindCount, null);
                    totalFlowRows += operationCount;
                    complete++;
                }
                if ((complete + failed + noPcode) % 100 == 0) {
                    println("P-code flow batch progress: " + (complete + failed + noPcode) + "/" + requests.size());
                }
            }
        } finally {
            decompiler.dispose();
        }
        println("GHIDRA_PROGRAM_PCODE_FLOW_FORMAT=" + ACQUISITION_FORMAT);
        println("requested=" + requests.size());
        println("max_total_seconds=" + maxTotalSeconds);
        println("complete=" + complete);
        println("no_pcode=" + noPcode);
        println("decompile_failed=" + failed);
        println("flow_rows=" + totalFlowRows);
        println("flow=" + flowFile);
        println("callind_evidence=" + evidenceFile);
        println("acquisition=" + acquisitionFile);
    }
}
