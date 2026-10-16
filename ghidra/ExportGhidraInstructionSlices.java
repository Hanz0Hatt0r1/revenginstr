// Export bounded disassembly and machine-P-code slices around exact addresses.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class ExportGhidraInstructionSlices extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraInstructionSlice/1";
    private static final int DEFAULT_LENGTH = 0x80;

    private Listing listing;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraInstructionSlices.java <output-jsonl> <address[:length]> [...]"
            );
        }
        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }
        listing = currentProgram.getListing();
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(output), StandardCharsets.UTF_8)))) {
            for (int i = 1; i < args.length && !monitor.isCancelled(); i++) {
                out.println(sliceRow(args[i]));
            }
        }
        println("Ghidra instruction slice export -> " + output);
    }

    private String sliceRow(String token) throws MemoryAccessException {
        String[] parts = token.split(":", 2);
        Address start = parseTargetAddress(parts[0]);
        int length = DEFAULT_LENGTH;
        if (parts.length == 2) {
            String raw = parts[1].trim().toLowerCase();
            if (raw.startsWith("0x")) raw = raw.substring(2);
            length = Integer.parseUnsignedInt(raw, 16);
        }
        if (start == null || length <= 0) {
            throw new IllegalArgumentException("invalid slice target: " + token);
        }
        Address end = start.add(length - 1L);
        Instruction exact = listing.getInstructionAt(start);
        StringBuilder instructions = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        InstructionIterator iterator = listing.getInstructions(new AddressSet(start, end), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getAddress().compareTo(start) < 0) continue;
            if (!first) instructions.append(',');
            first = false;
            instructions.append(instructionJson(instruction));
            count++;
        }
        instructions.append(']');
        return "{" +
            "\"format\":" + q(FORMAT) + "," +
            "\"program\":" + q(currentProgram.getName()) + "," +
            "\"requested\":" + q(parts[0]) + "," +
            "\"start\":" + q(addr(start)) + "," +
            "\"length\":" + length + "," +
            "\"exact_instruction_at_start\":" + (exact != null) + "," +
            "\"instruction_count\":" + count + "," +
            "\"instructions\":" + instructions +
            "}";
    }

    private Address parseTargetAddress(String token) {
        if (token == null) return null;
        String value = token.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        try { return toAddr(Long.parseUnsignedLong(value, 16)); }
        catch (RuntimeException exc) { return null; }
    }

    private String instructionJson(Instruction instruction) throws MemoryAccessException {
        StringBuilder operands = new StringBuilder("[");
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) operands.append(',');
            operands.append(q(instruction.getDefaultOperandRepresentation(index)));
        }
        operands.append(']');

        StringBuilder refs = new StringBuilder("[");
        boolean firstRef = true;
        for (Reference ref : instruction.getReferencesFrom()) {
            if (!firstRef) refs.append(',');
            firstRef = false;
            refs.append('{').append("\"to\":").append(q(addr(ref.getToAddress())))
                .append(',').append("\"type\":").append(q(ref.getReferenceType().getName())).append('}');
        }
        refs.append(']');

        StringBuilder flows = new StringBuilder("[");
        Address[] flowAddresses = instruction.getFlows();
        for (int index = 0; index < flowAddresses.length; index++) {
            if (index > 0) flows.append(',');
            flows.append(q(addr(flowAddresses[index])));
        }
        flows.append(']');

        StringBuilder pcode = new StringBuilder("[");
        PcodeOp[] pcodeOps = instruction.getPcode();
        for (int index = 0; index < pcodeOps.length; index++) {
            if (index > 0) pcode.append(',');
            PcodeOp op = pcodeOps[index];
            pcode.append('{').append("\"opcode\":").append(q(PcodeOp.getMnemonic(op.getOpcode())))
                .append(',').append("\"text\":").append(q(op.toString()))
                .append(',').append("\"output\":").append(varnodeJson(op.getOutput()))
                .append(',').append("\"inputs\":[");
            for (int inputIndex = 0; inputIndex < op.getNumInputs(); inputIndex++) {
                if (inputIndex > 0) pcode.append(',');
                pcode.append(varnodeJson(op.getInput(inputIndex)));
            }
            pcode.append("]}");
        }
        pcode.append(']');

        return "{" +
            "\"address\":" + q(addr(instruction.getAddress())) + "," +
            "\"bytes\":" + q(hex(instruction.getBytes())) + "," +
            "\"mnemonic\":" + q(instruction.getMnemonicString()) + "," +
            "\"text\":" + q(instruction.toString()) + "," +
            "\"operands\":" + operands + "," +
            "\"flow_type\":" + q(instruction.getFlowType().toString()) + "," +
            "\"fallthrough\":" + q(addr(instruction.getFallThrough())) + "," +
            "\"flows\":" + flows + "," +
            "\"references\":" + refs + "," +
            "\"pcode\":" + pcode + "}";
    }

    private static String varnodeJson(Varnode node) {
        if (node == null) return "null";
        Address address = node.getAddress();
        String space = address == null ? null : address.getAddressSpace().getName();
        return "{" + "\"text\":" + q(node.toString()) + ',' +
            "\"space\":" + q(space) + ',' +
            "\"offset\":" + q("0x" + Long.toUnsignedString(node.getOffset(), 16)) + ',' +
            "\"size\":" + node.getSize() + ',' +
            "\"constant\":" + node.isConstant() + ',' +
            "\"register\":" + node.isRegister() + ',' +
            "\"unique\":" + node.isUnique() + "}";
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
                default: if (c < 0x20) out.append(String.format("\\u%04x", (int)c)); else out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
