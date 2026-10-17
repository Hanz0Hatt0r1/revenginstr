import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

/** Export targeted or address-ordered corpus instruction and machine-P-code evidence. */
public class ExportGhidraFunctionInstructions extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1";
    private static final String CORPUS_FORMAT = "REVENGINSTR.GhidraFunctionInstructionCorpus/1";
    private Listing listing;
    private FunctionManager functions;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraFunctionInstructions.java <output.jsonl[.gz]> <function-address> [address ...] " +
                "or <output.jsonl.gz> --all [offset] [limit]");
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        if ("--all".equals(args[1])) {
            if (args.length > 4) throw new IllegalArgumentException("--all accepts only offset and limit");
            long offset = args.length > 2 ? parseBound(args[2], "offset") : 0;
            long limit = args.length > 3 ? parseBound(args[3], "limit") : 0;
            exportAll(output, offset, limit);
            return;
        }

        exportTargets(output, args);
    }

    private void exportTargets(File output, String[] args) throws Exception {
        java.util.List<String> missing = new java.util.ArrayList<>();
        try (BufferedWriter out = openWriter(output)) {
            for (int i = 1; i < args.length; i++) {
                monitor.checkCancelled();
                String token = args[i];
                Address address = parseTargetAddress(token);
                Function function = address == null ? null : functions.getFunctionAt(address);
                if (function == null) {
                    missing.add(token);
                    out.write(missingRow(token, address));
                } else {
                    writeFunctionRow(out, token, function);
                }
                out.newLine();
            }
        }
        if (!missing.isEmpty()) {
            throw new IllegalStateException("requested functions not found: " + String.join(", ", missing));
        }
        println("Ghidra function instruction export -> " + output);
    }

    private void exportAll(File output, long offset, long limit) throws Exception {
        long ordinal = 0;
        long exported = 0;
        long instructionCount = 0;
        Address first = null;
        Address last = null;
        try (BufferedWriter out = openWriter(output)) {
            FunctionIterator iterator = functions.getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                if (ordinal >= offset && (limit == 0 || exported < limit)) {
                    Address entry = function.getEntryPoint();
                    if (first == null) first = entry;
                    last = entry;
                    instructionCount += writeFunctionRow(out, addr(entry), function);
                    out.newLine();
                    exported++;
                    if ((exported % 1000) == 0) {
                        monitor.setMessage("Ghidra function corpus export: " + exported + " functions");
                    }
                }
                ordinal++;
            }
        }
        if (offset >= ordinal && ordinal > 0) {
            throw new IllegalArgumentException("function offset is outside the program inventory");
        }
        writeCorpusManifest(output, offset, limit, ordinal, exported, instructionCount, first, last);
        println("Ghidra function corpus export -> " + output + " (" + exported + "/" + ordinal + " functions)");
    }

    private void writeCorpusManifest(
            File output, long offset, long limit, long total, long exported,
            long instructionCount, Address first, Address last) throws Exception {
        File manifest = new File(output.getAbsolutePath() + ".manifest.json");
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(manifest), StandardCharsets.UTF_8))) {
            out.write("{\"format\":" + q(CORPUS_FORMAT) +
                ",\"program\":" + q(currentProgram.getName()) +
                ",\"executable_md5\":" + q(currentProgram.getExecutableMD5()) +
                ",\"language_id\":" + q(currentProgram.getLanguageID().toString()) +
                ",\"function_count\":" + total +
                ",\"function_offset\":" + offset +
                ",\"function_limit\":" + limit +
                ",\"exported_function_count\":" + exported +
                ",\"instruction_count\":" + instructionCount +
                ",\"first_function_address\":" + q(addr(first)) +
                ",\"last_function_address\":" + q(addr(last)) +
                ",\"complete\":" + (offset == 0 && (limit == 0 || limit >= total)) +
                ",\"gzip\":" + output.getName().endsWith(".gz") +
                ",\"output_sha256\":" + q(sha256(output)) + "}\n");
        }
    }

    private static long parseBound(String value, String name) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exc) {
            throw new IllegalArgumentException(name + " must be a non-negative integer");
        }
    }

    private static BufferedWriter openWriter(File output) throws Exception {
        OutputStream stream = new BufferedOutputStream(new FileOutputStream(output));
        if (output.getName().endsWith(".gz")) stream = new GZIPOutputStream(stream);
        return new BufferedWriter(new OutputStreamWriter(stream, StandardCharsets.UTF_8));
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (java.io.InputStream in = new java.io.BufferedInputStream(new java.io.FileInputStream(file))) {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = in.read(buffer)) >= 0) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    private Address parseTargetAddress(String token) {
        if (token == null) return null;
        String value = token.trim();
        if (value.startsWith("FUN_") || value.startsWith("fun_")) value = value.substring(4);
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        try {
            return toAddr(Long.parseUnsignedLong(value, 16));
        } catch (RuntimeException exc) {
            return null;
        }
    }

    private int writeFunctionRow(BufferedWriter out, String requested, Function function) throws Exception {
        out.write("{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(function.getEntryPoint())) +
            ",\"found\":true,\"function\":{" +
            "\"address\":" + q(addr(function.getEntryPoint())) +
            ",\"name\":" + q(function.getName()) +
            ",\"size\":" + function.getBody().getNumAddresses() +
            ",\"calling_convention\":" + q(function.getCallingConventionName()) +
            "},\"instruction_count\":");
        int count = 0;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) { monitor.checkCancelled(); iterator.next(); count++; }
        out.write(Integer.toString(count));
        out.write(",\"instructions\":[");
        iterator = listing.getInstructions(function.getBody(), true);
        boolean first = true;
        int written = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (!first) out.write(',');
            first = false;
            out.write(instructionJson(iterator.next()));
            written++;
        }
        if (written != count) throw new IllegalStateException("function instruction count changed during export");
        out.write("]}");
        return count;
    }

    private String missingRow(String requested, Address address) {
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(address)) +
            ",\"found\":false,\"function\":null,\"instruction_count\":0,\"instructions\":[]}";
    }

    private String instructionJson(Instruction instruction) throws MemoryAccessException {
        StringBuilder operands = new StringBuilder("[");
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            if (i > 0) operands.append(',');
            operands.append(q(instruction.getDefaultOperandRepresentation(i)));
        }
        operands.append(']');

        StringBuilder references = new StringBuilder("[");
        boolean firstReference = true;
        for (Reference ref : instruction.getReferencesFrom()) {
            if (!firstReference) references.append(',');
            firstReference = false;
            references.append("{\"to\":").append(q(addr(ref.getToAddress())))
                .append(",\"type\":").append(q(ref.getReferenceType().getName())).append('}');
        }
        references.append(']');

        StringBuilder flows = new StringBuilder("[");
        Address[] flowAddresses = instruction.getFlows();
        for (int i = 0; i < flowAddresses.length; i++) {
            if (i > 0) flows.append(',');
            flows.append(q(addr(flowAddresses[i])));
        }
        flows.append(']');

        StringBuilder pcode = new StringBuilder("[");
        PcodeOp[] operations = instruction.getPcode();
        for (int i = 0; i < operations.length; i++) {
            if (i > 0) pcode.append(',');
            PcodeOp op = operations[i];
            pcode.append("{\"opcode\":").append(q(PcodeOp.getMnemonic(op.getOpcode())))
                .append(",\"text\":").append(q(op.toString()))
                .append(",\"output\":").append(varnodeJson(op.getOutput())).append(",\"inputs\":[");
            for (int j = 0; j < op.getNumInputs(); j++) {
                if (j > 0) pcode.append(',');
                pcode.append(varnodeJson(op.getInput(j)));
            }
            pcode.append("]}");
        }
        pcode.append(']');

        return "{\"address\":" + q(addr(instruction.getAddress())) +
            ",\"bytes\":" + q(hex(instruction.getBytes())) +
            ",\"mnemonic\":" + q(instruction.getMnemonicString()) +
            ",\"text\":" + q(instruction.toString()) +
            ",\"operands\":" + operands +
            ",\"flow_type\":" + q(instruction.getFlowType().toString()) +
            ",\"fallthrough\":" + q(addr(instruction.getFallThrough())) +
            ",\"flows\":" + flows +
            ",\"references\":" + references +
            ",\"pcode\":" + pcode + "}";
    }

    private static String varnodeJson(Varnode node) {
        if (node == null) return "null";
        Address address = node.getAddress();
        String space = address == null ? null : address.getAddressSpace().getName();
        return "{\"text\":" + q(node.toString()) +
            ",\"space\":" + q(space) +
            ",\"offset\":" + q("0x" + Long.toUnsignedString(node.getOffset(), 16)) +
            ",\"size\":" + node.getSize() +
            ",\"constant\":" + node.isConstant() +
            ",\"register\":" + node.isRegister() +
            ",\"unique\":" + node.isUnique() + "}";
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
        return out.toString();
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
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
