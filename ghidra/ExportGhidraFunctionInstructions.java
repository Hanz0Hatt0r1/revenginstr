import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;

/** Export targeted or address-ordered corpus instruction and machine-P-code evidence. */
public class ExportGhidraFunctionInstructions extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1";
    private static final String CORPUS_FORMAT = "REVENGINSTR.GhidraFunctionInstructionCorpus/1";
    private static final long MAX_RECOVERED_BYTES = 0x1000;
    private Listing listing;
    private FunctionManager functions;
    private PseudoDisassembler pseudoDisassembler;
    private final Map<Address, Boolean> returningFunctionCache = new HashMap<>();

    private static class FunctionInstructions {
        final List<Instruction> ordered;
        final Set<Address> restoredCalls;

        FunctionInstructions(TreeMap<Address, Instruction> instructions, Set<Address> restoredCalls) {
            this.ordered = new ArrayList<>(instructions.values());
            this.restoredCalls = restoredCalls;
        }
    }

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
        pseudoDisassembler = new PseudoDisassembler(currentProgram);
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
                boolean entrypoint = isEntrypointToken(token);
                Address address = parseTargetAddress(token);
                Function function = address == null ? null : functions.getFunctionAt(address);
                if (function == null && entrypoint && address != null) {
                    if (writeEntrypointRow(out, token, address) == 0) {
                        missing.add(token);
                        out.write(missingRow(token, address));
                    }
                } else if (function == null) {
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
        if (value.regionMatches(true, 0, "entry:", 0, 6)) value = value.substring(6).trim();
        if (value.startsWith("FUN_") || value.startsWith("fun_")) value = value.substring(4);
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        try {
            return toAddr(Long.parseUnsignedLong(value, 16));
        } catch (RuntimeException exc) {
            return null;
        }
    }

    private boolean isEntrypointToken(String token) {
        return token != null && token.trim().regionMatches(true, 0, "entry:", 0, 6);
    }

    private int writeFunctionRow(BufferedWriter out, String requested, Function function) throws Exception {
        FunctionInstructions exported = collectFunctionInstructions(function);
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
        int count = exported.ordered.size();
        out.write(Integer.toString(count));
        out.write(",\"instructions\":[");
        boolean first = true;
        int written = 0;
        for (Instruction instruction : exported.ordered) {
            monitor.checkCancelled();
            if (!first) out.write(',');
            first = false;
            out.write(instructionJson(instruction,
                exported.restoredCalls.contains(instruction.getAddress())));
            written++;
        }
        if (written != count) throw new IllegalStateException("function instruction count changed during export");
        out.write("]}");
        return count;
    }

    private FunctionInstructions collectFunctionInstructions(Function function) throws Exception {
        TreeMap<Address, Instruction> instructions = new TreeMap<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            instructions.put(instruction.getAddress(), instruction);
        }

        Set<Address> restoredCalls = new HashSet<>();
        ArrayDeque<Instruction> pending = new ArrayDeque<>();
        for (Instruction instruction : instructions.values()) {
            if (isReturningDirectCall(instruction)) pending.addLast(instruction);
        }

        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Instruction call = pending.removeFirst();
            Address nextAddress = call.getAddress().add(call.getLength());
            Instruction next = instructionAt(nextAddress);
            if (next == null || !isSafeRecoveryAddress(function, nextAddress, nextAddress)) continue;

            restoredCalls.add(call.getAddress());
            ArrayDeque<Address> work = new ArrayDeque<>();
            Set<Address> visited = new HashSet<>();
            work.addLast(nextAddress);
            long recoveredBytes = 0;
            while (!work.isEmpty()) {
                monitor.checkCancelled();
                Address address = work.removeFirst();
                if (instructions.containsKey(address) || !visited.add(address) ||
                        !isSafeRecoveryAddress(function, address, nextAddress)) continue;
                Instruction instruction = instructionAt(address);
                if (instruction == null) continue;
                recoveredBytes += instruction.getLength();
                if (recoveredBytes > MAX_RECOVERED_BYTES) break;
                instructions.put(address, instruction);

                if (isReturningDirectCall(instruction)) {
                    pending.addLast(instruction);
                    continue;
                }
                addRecoverySuccessors(instruction, work);
            }
        }
        return new FunctionInstructions(instructions, restoredCalls);
    }

    private int writeEntrypointRow(BufferedWriter out, String requested, Address entry) throws Exception {
        FunctionInstructions exported = collectEntrypointInstructions(entry);
        if (exported.ordered.isEmpty()) return 0;
        int size = 0;
        for (Instruction instruction : exported.ordered) size += instruction.getLength();
        out.write("{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(entry)) +
            ",\"found\":true,\"function\":{\"address\":" + q(addr(entry)) +
            ",\"name\":" + q("ENTRY_" + entry.toString(false, false)) +
            ",\"size\":" + size + ",\"calling_convention\":null},\"instruction_count\":" +
            exported.ordered.size() + ",\"instructions\":[");
        boolean first = true;
        for (Instruction instruction : exported.ordered) {
            monitor.checkCancelled();
            if (!first) out.write(',');
            first = false;
            out.write(instructionJson(instruction,
                exported.restoredCalls.contains(instruction.getAddress())));
        }
        out.write("]}");
        return exported.ordered.size();
    }

    private FunctionInstructions collectEntrypointInstructions(Address entry) throws Exception {
        TreeMap<Address, Instruction> instructions = new TreeMap<>();
        Set<Address> restoredCalls = new HashSet<>();
        ArrayDeque<Address> work = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        work.addLast(entry);
        long recoveredBytes = 0;
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address address = work.removeFirst();
            if (instructions.containsKey(address) || !visited.add(address) ||
                    !isSafeEntrypointAddress(entry, address)) continue;
            Instruction instruction = instructionAt(address);
            if (instruction == null) continue;
            recoveredBytes += instruction.getLength();
            if (recoveredBytes > MAX_RECOVERED_BYTES) break;
            instructions.put(address, instruction);
            if (isReturningDirectCall(instruction)) {
                Address fallthrough = instruction.getAddress().add(instruction.getLength());
                if (instructionAt(fallthrough) != null &&
                        isSafeEntrypointAddress(entry, fallthrough)) {
                    restoredCalls.add(instruction.getAddress());
                    work.addLast(fallthrough);
                }
            } else {
                addRecoverySuccessors(instruction, work);
            }
        }
        return new FunctionInstructions(instructions, restoredCalls);
    }

    private boolean isSafeEntrypointAddress(Address entry, Address address) {
        long distance;
        try {
            distance = address.subtract(entry);
        } catch (RuntimeException exc) {
            return false;
        }
        if (distance < -MAX_RECOVERED_BYTES || distance > MAX_RECOVERED_BYTES) return false;
        Function owner = functions.getFunctionContaining(address);
        if (owner != null) return owner.getEntryPoint().equals(entry);
        return functions.getFunctionAt(address) == null;
    }

    private Instruction instructionAt(Address address) {
        Instruction instruction = listing.getInstructionAt(address);
        if (instruction != null) return instruction;
        try {
            return pseudoDisassembler.disassemble(address);
        } catch (Exception exc) {
            return null;
        }
    }

    private boolean isSafeRecoveryAddress(Function function, Address address, Address origin) {
        long distance;
        try {
            distance = address.subtract(origin);
        } catch (RuntimeException exc) {
            return false;
        }
        if (distance < -MAX_RECOVERED_BYTES || distance > MAX_RECOVERED_BYTES) return false;
        Function owner = functions.getFunctionContaining(address);
        if (owner != null && !owner.getEntryPoint().equals(function.getEntryPoint())) return false;
        Function entry = functions.getFunctionAt(address);
        return entry == null || entry.getEntryPoint().equals(function.getEntryPoint());
    }

    private void addRecoverySuccessors(Instruction instruction, ArrayDeque<Address> work) {
        String flow = instruction.getFlowType().toString();
        if ("TERMINATOR".equals(flow) || "CALL_TERMINATOR".equals(flow) ||
                "COMPUTED_CALL_TERMINATOR".equals(flow)) return;
        if ("UNCONDITIONAL_JUMP".equals(flow) || "COMPUTED_JUMP".equals(flow) ||
                "CONDITIONAL_JUMP".equals(flow)) {
            for (Address target : instruction.getFlows()) work.addLast(target);
            if (!"CONDITIONAL_JUMP".equals(flow)) return;
        }
        if ("UNCONDITIONAL_CALL".equals(flow) || "COMPUTED_CALL".equals(flow) ||
                "FALL_THROUGH".equals(flow) || "CONDITIONAL_JUMP".equals(flow)) {
            Address fallthrough = instruction.getAddress().add(instruction.getLength());
            work.addLast(fallthrough);
        }
    }

    private boolean isReturningDirectCall(Instruction instruction) throws Exception {
        if (!"CALL_TERMINATOR".equals(instruction.getFlowType().toString()) ||
                !"CALL".equalsIgnoreCase(instruction.getMnemonicString())) return false;
        Address[] targets = instruction.getFlows();
        if (targets.length != 1) return false;
        Function target = functions.getFunctionAt(targets[0]);
        if (target == null) target = functions.getFunctionContaining(targets[0]);
        return target != null && functionHasReturn(target);
    }

    private boolean functionHasReturn(Function function) throws Exception {
        Address entry = function.getEntryPoint();
        Boolean cached = returningFunctionCache.get(entry);
        if (cached != null) return cached;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            for (PcodeOp operation : iterator.next().getPcode()) {
                if (operation.getOpcode() == PcodeOp.RETURN) {
                    returningFunctionCache.put(entry, true);
                    return true;
                }
            }
        }
        returningFunctionCache.put(entry, false);
        return false;
    }

    private String missingRow(String requested, Address address) {
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(address)) +
            ",\"found\":false,\"function\":null,\"instruction_count\":0,\"instructions\":[]}";
    }

    private String instructionJson(Instruction instruction, boolean restoredCall) throws MemoryAccessException {
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

        Address fallthrough = restoredCall ? instruction.getAddress().add(instruction.getLength()) :
            instruction.getFallThrough();
        String flowType = restoredCall ? "UNCONDITIONAL_CALL" : instruction.getFlowType().toString();
        return "{\"address\":" + q(addr(instruction.getAddress())) +
            ",\"bytes\":" + q(hex(instruction.getBytes())) +
            ",\"mnemonic\":" + q(instruction.getMnemonicString()) +
            ",\"text\":" + q(instruction.toString()) +
            ",\"operands\":" + operands +
            ",\"flow_type\":" + q(flowType) +
            ",\"fallthrough\":" + q(addr(fallthrough)) +
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
