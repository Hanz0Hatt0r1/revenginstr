import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Export targeted instruction and machine-P-code evidence from a Ghidra program. */
public class ExportGhidraFunctionInstructions extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1";
    private Listing listing;
    private FunctionManager functions;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraFunctionInstructions.java <output.jsonl> <function-address> [address ...]");
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        List<String> missing = new ArrayList<>();
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (int i = 1; i < args.length; i++) {
                monitor.checkCancelled();
                String token = args[i];
                Address address = parseTargetAddress(token);
                Function function = address == null ? null : functions.getFunctionAt(address);
                if (function == null) {
                    missing.add(token);
                    out.write(missingRow(token, address));
                } else {
                    out.write(functionRow(token, function));
                }
                out.newLine();
            }
        }

        if (!missing.isEmpty()) {
            throw new IllegalStateException("requested functions not found: " + String.join(", ", missing));
        }
        println("Ghidra function instruction export -> " + output);
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

    private String functionRow(String requested, Function function) throws Exception {
        StringBuilder instructions = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (!first) instructions.append(',');
            first = false;
            instructions.append(instructionJson(iterator.next()));
            count++;
        }
        instructions.append(']');
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(function.getEntryPoint())) +
            ",\"found\":true,\"function\":{" +
            "\"address\":" + q(addr(function.getEntryPoint())) +
            ",\"name\":" + q(function.getName()) +
            ",\"size\":" + function.getBody().getNumAddresses() +
            ",\"calling_convention\":" + q(function.getCallingConventionName()) + "}" +
            ",\"instruction_count\":" + count + ",\"instructions\":" + instructions + "}";
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
