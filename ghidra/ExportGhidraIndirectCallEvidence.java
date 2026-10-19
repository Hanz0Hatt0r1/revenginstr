import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
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
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** Export bounded High-P-code target expressions for indirect calls in one function. */
public class ExportGhidraIndirectCallEvidence extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraIndirectCallEvidence/4";
    private static final int MAX_DEPTH = 6;

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

    @Override
    protected void run() throws Exception {
        String executableSha256 = currentProgram.getExecutableSHA256();
        if (executableSha256 == null || !executableSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalStateException("Current program has no valid executable SHA-256");
        }
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraIndirectCallEvidence.java <function-address-or-name> <output.jsonl>");
        }
        Function function = resolveFunction(args[0]);
        File output = new File(args[1]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open current program in decompiler");
        }
        int indirectCalls = 0;
        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results == null || !results.decompileCompleted()) {
                String message = results == null ? "no result" : results.getErrorMessage();
                throw new IllegalStateException("Decompile failed for " + function.getName(true) + ": " + message);
            }
            HighFunction high = results.getHighFunction();
            if (high == null) throw new IllegalStateException("No HighFunction for " + function.getName(true));

            try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(output), StandardCharsets.UTF_8))) {
                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                while (operations.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST op = operations.next();
                    if (op.getOpcode() != PcodeOp.CALLIND || op.getNumInputs() < 1) continue;
                    out.write(row(args[0], function, op, high));
                    out.newLine();
                    indirectCalls++;
                }
            }
        } finally {
            decompiler.dispose();
        }
        println("Exported " + indirectCalls + " indirect-call rows for " + function.getName(true) +
            " at " + function.getEntryPoint() + " -> " + output);
    }

    private Function resolveFunction(String token) throws Exception {
        Address address = null;
        try {
            address = toAddr(token);
        } catch (Exception ignored) {
            // Fall through to name lookup.
        }
        if (address != null) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) function = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (function != null) return function;
        }
        Function exact = null;
        Function partial = null;
        int partialCount = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next();
            String shortName = function.getName();
            String fullName = function.getName(true);
            if (token.equals(shortName) || token.equals(fullName)) {
                exact = function;
                break;
            }
            if (shortName.contains(token) || fullName.contains(token)) {
                partial = function;
                partialCount++;
            }
        }
        if (exact != null) return exact;
        if (partialCount == 1) return partial;
        if (partialCount > 1) throw new IllegalArgumentException("Ambiguous function token: " + token);
        throw new IllegalArgumentException("Function not found: " + token);
    }

    private String row(String requested, Function function, PcodeOpAST op, HighFunction high) {
        SequenceNumber seq = op.getSeqnum();
        Varnode target = op.getNumInputs() > 0 ? op.getInput(0) : null;
        TargetResolution resolution = resolveTarget(target, 0);
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"program_sha256\":" + q(currentProgram.getExecutableSHA256()) +
            ",\"architecture\":" + architectureJson() +
            ",\"requested\":" + q(requested) +
            ",\"function_entry\":" + q(addr(function.getEntryPoint())) +
            ",\"call_address\":" + q(addr(seq.getTarget())) +
            ",\"call_time\":" + seq.getTime() +
            ",\"target\":" + q(nodeToken(target)) +
            ",\"target_expression\":" + q(expression(target, 0, new HashSet<String>())) +
            ",\"target_resolution\":" + targetResolutionJson(resolution) +
            ",\"parameter_roots\":" + parameterRootsJson(high, op, resolution.functionEntry != null) +
            ",\"arg_count\":" + Math.max(0, op.getNumInputs() - 1) + "}";
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
                .append(",\"argument_token\":").append(q(nodeToken(argument))).append('}');
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
        return "{\"status\":" + q(resolution.status) +
            ",\"slot_address\":" + q(resolution.slot == null ? null : addr(resolution.slot)) +
            ",\"function_entry\":" + q(resolution.functionEntry == null ? null : addr(resolution.functionEntry)) + "}";
    }

    private TargetResolution resolveTarget(Varnode value, int depth) {
        if (value == null || depth > MAX_DEPTH) return unresolved("unsupported_target_expression", null);
        if (value.isAddress()) {
            return depth == 0
                ? unresolved("unsupported_target_expression", null)
                : resolveFunctionPointer(value.getAddress());
        }
        if (value.isConstant()) {
            Address target = addressFromOffset(value.getOffset());
            return resolveFunctionAt(target, "resolved_constant_function", null);
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
        Address target = addressFromOffset(pointer.longValue());
        return resolveFunctionAt(target, "resolved_static_function_pointer", slot);
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

    private String architectureJson() {
        return "{\"language_id\":" + q(currentProgram.getLanguageID().toString()) +
            ",\"pointer_width_bytes\":" + currentProgram.getDefaultPointerSize() +
            ",\"endianness\":" + q(currentProgram.getLanguage().isBigEndian() ? "big" : "little") + "}";
    }

    private String nodeToken(Varnode node) {
        if (node == null) return "none";
        if (node.isConstant()) {
            return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        }
        PcodeOp def = node.getDef();
        if (def != null) {
            SequenceNumber seq = def.getSeqnum();
            return "def:" + def.getMnemonic() + "@" + cell(seq.getTarget()) + ":" + seq.getTime() + ":" + node.getSize();
        }
        if (node.isRegister()) return "register:" + cell(node.getAddress()) + ":" + node.getSize();
        if (node.isUnique()) return "unique:" + cell(node.getAddress()) + ":" + node.getSize();
        if (node.isAddress()) return "address:" + cell(node.getAddress()) + ":" + node.getSize();
        return "input:" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private String expression(Varnode node, int depth, Set<String> seen) {
        if (node == null) return "none";
        String token = nodeToken(node);
        if (depth >= MAX_DEPTH) return token + "{depth-limit}";
        if (!seen.add(token)) return token + "{cycle}";
        PcodeOp def = node.getDef();
        if (def == null) return token;

        int opcode = def.getOpcode();
        StringBuilder out = new StringBuilder(def.getMnemonic()).append('(');
        int start = opcode == PcodeOp.LOAD ? Math.min(1, def.getNumInputs()) : 0;
        if (opcode == PcodeOp.INDIRECT) {
            int count = Math.min(1, def.getNumInputs());
            for (int i = 0; i < count; i++) {
                if (i > 0) out.append(',');
                out.append(expression(def.getInput(i), depth + 1, new HashSet<String>(seen)));
            }
            return out.append(')').toString();
        }
        for (int i = start; i < def.getNumInputs(); i++) {
            if (i > start) out.append(',');
            out.append(expression(def.getInput(i), depth + 1, new HashSet<String>(seen)));
        }
        return out.append(')').toString();
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
    }

    private static String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private static String q(String value) {
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
}
