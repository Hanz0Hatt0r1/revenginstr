import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Generic architecture-normalized high-P-code exporter for revenginstr. */
public class PortablePcodeCorpusExporter extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.PcodeCorpus/1";
    private static final long SMALL_CONST_MAX = 0x1000L;
    private static final int MAX_MODEL_OPS = 256;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    private static class ModelRecord {
        String text;
        int ops;
        int emittedOps;
        int calls;
        int indirectCalls;
        int branches;
        int loads;
        int stores;
        boolean truncated;
    }

    private String json(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
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

    private String seqKey(SequenceNumber sequence) {
        return sequence.getTarget().toString() + ":" + sequence.getTime();
    }

    private String constantToken(Varnode node) {
        long value = node.getOffset();
        int size = node.getSize();
        if (value == 0L) return "const:zero:" + size;
        if (value == 1L) return "const:one:" + size;
        long mask = size >= 8 ? -1L : ((1L << (size * 8)) - 1L);
        if (value == mask) return "const:allones:" + size;
        if (Long.compareUnsigned(value, SMALL_CONST_MAX) <= 0) {
            return "const:small:0x" + Long.toUnsignedString(value, 16) + ":" + size;
        }
        return "const:large:" + size;
    }

    private String varnodeToken(Varnode node, Map<String, Integer> opIds) {
        if (node == null) return "none";
        if (node.isConstant()) return constantToken(node);
        PcodeOp definition = node.getDef();
        if (definition != null) {
            Integer id = opIds.get(seqKey(definition.getSeqnum()));
            if (id != null) return "v" + id + ":" + node.getSize();
            return "def:omitted:" + node.getSize();
        }
        if (node.isRegister()) return "reg:" + node.getSize();
        if (node.isUnique()) return "tmp:" + node.getSize();
        if (node.isAddress()) return "mem:" + node.getSize();
        return "input:" + node.getSize();
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
        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionAt(target);
        if (function != null) return function;

        // Some ABIs tag code pointers in the low bit. Normalize only as a
        // fallback and only accept the address when Ghidra has a function there.
        long offset = target.getOffset();
        if ((offset & 1L) == 0L) return null;
        try {
            Address normalized = target.getAddressSpace().getAddress(offset & ~1L);
            return functions.getFunctionAt(normalized);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String callKind(PcodeOpAST op) {
        if (op.getOpcode() == PcodeOp.CALLIND) return "call:indirect";
        if (op.getOpcode() != PcodeOp.CALL) return null;
        Function function = resolveCallTarget(op);
        if (function == null) return "call:unresolved";
        return function.isExternal() ? "call:external" : "call:internal";
    }

    private String countBucket(long value) {
        if (value <= 0) return "0";
        if (value == 1) return "1";
        long lower = 2;
        long upper = 3;
        while (upper < value && upper < 65535) {
            lower = upper + 1;
            upper = (upper << 1) + 1;
        }
        if (upper >= 65535 && value > upper) return "65536+";
        return lower + "-" + upper;
    }

    private String[] normalizedArchitecture() {
        String raw = currentProgram.getLanguageID().toString();
        String[] parts = raw.split(":");
        String processor = parts.length > 0 ? parts[0].toUpperCase(Locale.ROOT) : "UNKNOWN";
        String endian = parts.length > 1 ? parts[1].toUpperCase(Locale.ROOT) : "UNKNOWN";
        String bits = parts.length > 2 ? parts[2] : "";
        String arch = processor;
        String pointerSize = "unknown";
        try {
            int bitCount = Integer.parseInt(bits);
            arch = processor + bitCount;
            if (bitCount > 0 && bitCount % 8 == 0) pointerSize = Integer.toString(bitCount / 8);
        } catch (NumberFormatException ignored) {
        }
        return new String[] {arch, endian, pointerSize};
    }

    private List<PcodeOpAST> selectModelOps(List<PcodeOpAST> all) {
        if (all.size() <= MAX_MODEL_OPS) return new ArrayList<>(all);
        int head = MAX_MODEL_OPS / 2;
        int tail = MAX_MODEL_OPS - head;
        List<PcodeOpAST> selected = new ArrayList<>(MAX_MODEL_OPS);
        selected.addAll(all.subList(0, head));
        selected.addAll(all.subList(all.size() - tail, all.size()));
        return selected;
    }

    private void appendInputs(StringBuilder text, PcodeOpAST op, Map<String, Integer> opIds,
                              int start, String label) {
        for (int i = start; i < op.getNumInputs(); i++) {
            text.append(' ').append(label).append('=').append(varnodeToken(op.getInput(i), opIds));
        }
    }

    private void appendOperands(StringBuilder text, PcodeOpAST op, Map<String, Integer> opIds) {
        int opcode = op.getOpcode();
        int inputs = op.getNumInputs();
        if (opcode == PcodeOp.LOAD) {
            if (inputs >= 2) text.append(" addr=").append(varnodeToken(op.getInput(1), opIds));
            return;
        }
        if (opcode == PcodeOp.STORE) {
            if (inputs >= 2) text.append(" addr=").append(varnodeToken(op.getInput(1), opIds));
            if (inputs >= 3) text.append(" value=").append(varnodeToken(op.getInput(2), opIds));
            return;
        }
        if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
            appendInputs(text, op, opIds, 1, "arg");
            return;
        }
        if (opcode == PcodeOp.BRANCH) return;
        if (opcode == PcodeOp.CBRANCH) {
            if (inputs >= 2) text.append(" cond=").append(varnodeToken(op.getInput(1), opIds));
            return;
        }
        if (opcode == PcodeOp.RETURN) {
            appendInputs(text, op, opIds, Math.min(1, inputs), "ret");
            return;
        }
        if (opcode == PcodeOp.INDIRECT) {
            if (inputs >= 1) text.append(" in=").append(varnodeToken(op.getInput(0), opIds));
            return;
        }
        appendInputs(text, op, opIds, 0, "in");
    }

    private ModelRecord buildModelRecord(Function function, HighFunction high) {
        List<PcodeOpAST> all = new ArrayList<>();
        Iterator<PcodeOpAST> iterator = high.getPcodeOps();
        ModelRecord record = new ModelRecord();
        while (iterator.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST op = iterator.next();
            all.add(op);
            switch (op.getOpcode()) {
                case PcodeOp.CALL: record.calls++; break;
                case PcodeOp.CALLIND: record.calls++; record.indirectCalls++; break;
                case PcodeOp.BRANCH:
                case PcodeOp.CBRANCH:
                case PcodeOp.BRANCHIND: record.branches++; break;
                case PcodeOp.LOAD: record.loads++; break;
                case PcodeOp.STORE: record.stores++; break;
                default: break;
            }
        }
        record.ops = all.size();
        List<PcodeOpAST> selected = selectModelOps(all);
        record.emittedOps = selected.size();
        record.truncated = selected.size() != all.size();

        Map<String, Integer> opIds = new HashMap<>();
        for (int i = 0; i < selected.size(); i++) opIds.put(seqKey(selected.get(i).getSeqnum()), i);

        String[] architecture = normalizedArchitecture();
        StringBuilder text = new StringBuilder();
        text.append("ARCH=").append(architecture[0]).append('\n');
        text.append("ENDIAN=").append(architecture[1]).append('\n');
        text.append("PTR_SIZE=").append(architecture[2]).append('\n');
        text.append("CALLCONV=").append(function.getCallingConventionName()).append('\n');
        text.append("PARAMS=").append(function.getParameterCount()).append('\n');
        text.append("BODY_ADDRS_BUCKET=").append(countBucket(function.getBody().getNumAddresses())).append('\n');
        text.append("OPS_BUCKET=").append(countBucket(record.ops)).append('\n');
        text.append("CALLS_BUCKET=").append(countBucket(record.calls)).append('\n');
        text.append("INDIRECT_CALLS_BUCKET=").append(countBucket(record.indirectCalls)).append('\n');
        text.append("BRANCHES_BUCKET=").append(countBucket(record.branches)).append('\n');
        text.append("LOADS_BUCKET=").append(countBucket(record.loads)).append('\n');
        text.append("STORES_BUCKET=").append(countBucket(record.stores)).append('\n');
        text.append("TRUNCATED=").append(record.truncated ? "1" : "0").append('\n');

        for (int i = 0; i < selected.size(); i++) {
            PcodeOpAST op = selected.get(i);
            text.append('o').append(i).append(' ').append(op.getMnemonic());
            String kind = callKind(op);
            if (kind != null) text.append(' ').append(kind);
            Varnode output = op.getOutput();
            if (output != null) text.append(" out=").append(varnodeToken(output, opIds));
            appendOperands(text, op, opIds);
            text.append('\n');
        }
        record.text = text.toString();
        return record;
    }

    private void writeSuccess(BufferedWriter out, Function function, ModelRecord record) throws Exception {
        out.write("{" +
            "\"format\":" + json(FORMAT) + "," +
            "\"program\":" + json(currentProgram.getName()) + "," +
            "\"source_entry\":" + json(function.getEntryPoint().toString()) + "," +
            "\"source_name\":" + json(function.getName(true)) + "," +
            "\"external\":false," +
            "\"decompile_status\":\"ok\"," +
            "\"metrics\":{" +
                "\"ops\":" + record.ops + "," +
                "\"emitted_ops\":" + record.emittedOps + "," +
                "\"calls\":" + record.calls + "," +
                "\"indirect_calls\":" + record.indirectCalls + "," +
                "\"branches\":" + record.branches + "," +
                "\"loads\":" + record.loads + "," +
                "\"stores\":" + record.stores + "," +
                "\"truncated\":" + record.truncated +
            "}," +
            "\"model_text\":" + json(record.text) +
            "}");
        out.newLine();
    }

    private void writeFailure(BufferedWriter out, Function function, String message) throws Exception {
        out.write("{" +
            "\"format\":" + json(FORMAT) + "," +
            "\"program\":" + json(currentProgram.getName()) + "," +
            "\"source_entry\":" + json(function.getEntryPoint().toString()) + "," +
            "\"source_name\":" + json(function.getName(true)) + "," +
            "\"external\":false," +
            "\"decompile_status\":\"failed\"," +
            "\"error\":" + json(message == null ? "unknown decompiler failure" : message) +
            "}");
        out.newLine();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 3) {
            printerr("usage: PortablePcodeCorpusExporter.java <output.jsonl> [max-functions] [name-contains]");
            return;
        }
        File output = new File(args[0]);
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        int maxFunctions = args.length >= 2 && !args[1].isEmpty() ? Integer.parseInt(args[1]) : 0;
        String nameContains = args.length >= 3 ? args[2] : "";

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int seen = 0;
        int ok = 0;
        int failed = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal()) continue;
                if (!nameContains.isEmpty() && !function.getName(true).contains(nameContains)) continue;
                if (maxFunctions > 0 && seen >= maxFunctions) break;
                seen++;
                try {
                    DecompileResults results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
                    HighFunction high = results == null ? null : results.getHighFunction();
                    if (results != null && results.decompileCompleted() && high != null) {
                        writeSuccess(out, function, buildModelRecord(function, high));
                        ok++;
                    } else {
                        String message = results == null ? "no decompiler result" : results.getErrorMessage();
                        writeFailure(out, function, message);
                        failed++;
                    }
                } catch (Exception error) {
                    writeFailure(out, function, error.toString());
                    failed++;
                }
                if (seen % 250 == 0) println("Portable P-code export progress: " + seen + " functions");
            }
        } finally {
            decompiler.dispose();
        }
        println("format: " + FORMAT);
        println("functions: " + seen);
        println("ok: " + ok);
        println("failed: " + failed);
        println("output: " + output.getAbsolutePath());
    }
}
