import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** Export bounded High-P-code target expressions for indirect calls in one function. */
public class ExportGhidraIndirectCallEvidence extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraIndirectCallEvidence/2";
    private static final int MAX_DEPTH = 6;

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
                    SequenceNumber seq = op.getSeqnum();
                    Varnode target = op.getInput(0);
                    out.write(row(args[0], function, seq, target, op.getNumInputs()));
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

    private String row(String requested, Function function, SequenceNumber seq,
            Varnode target, int inputCount) {
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
            ",\"arg_count\":" + Math.max(0, inputCount - 1) + "}";
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
