import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Export numeric operands and referenced numeric data as generic JSONL evidence. */
public class ExportGhidraFunctionOperands extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionOperand/1";
    private BufferedWriter out;
    private Function function;
    private String requested;
    private final Set<String> seenReferencedData = new HashSet<>();
    private long rows;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraFunctionOperands.java <function-address-or-name> <output.jsonl>");
        }
        requested = args[0];
        function = resolveFunction(requested);

        File output = new File(args[1]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out = writer;
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    for (Object object : instruction.getOpObjects(operand)) {
                        if (object instanceof Scalar) {
                            writeScalar(instruction.getAddress(), operand, "immediate",
                                (Scalar)object, null, null);
                        } else if (object instanceof Address) {
                            writeReferencedData(instruction.getAddress(), operand, (Address)object);
                        }
                    }
                }
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (!reference.getReferenceType().isCall()) {
                        writeReferencedData(instruction.getAddress(), reference.getOperandIndex(),
                            reference.getToAddress());
                    }
                }
            }
        }
        println("Exported " + rows + " numeric operand/data rows for " +
            function.getName(true) + " at " + function.getEntryPoint() + " -> " + output);
    }

    private Function resolveFunction(String token) {
        Address address = resolveAddress(token);
        if (address != null) {
            Function match = currentProgram.getFunctionManager().getFunctionAt(address);
            if (match == null) match = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (match != null) return match;
        }

        Function exact = null;
        Function partial = null;
        int partialCount = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function candidate = iterator.next();
            if (token.equals(candidate.getName()) || token.equals(candidate.getName(true))) {
                exact = candidate;
                break;
            }
            if (candidate.getName().contains(token) || candidate.getName(true).contains(token)) {
                partial = candidate;
                partialCount++;
            }
        }
        if (exact != null) return exact;
        if (partialCount == 1) return partial;
        if (partialCount > 1) throw new IllegalArgumentException("Ambiguous function token: " + token);
        throw new IllegalArgumentException("Function not found: " + token);
    }

    private Address resolveAddress(String token) {
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

    private void writeReferencedData(Address instruction, int operand, Address target) throws Exception {
        if (target == null) return;
        Data data = currentProgram.getListing().getDataAt(target);
        if (data == null) return;
        Object value = data.getValue();
        if (!(value instanceof Scalar) && !(value instanceof Number)) return;
        String key = instruction + ":" + operand + ":" + target;
        if (!seenReferencedData.add(key)) return;
        String dataType = data.getDataType().getName();
        if (value instanceof Scalar) {
            writeScalar(instruction, operand, "referenced-scalar", (Scalar)value, target, dataType);
        } else {
            writeNumber(instruction, operand, (Number)value, target, dataType);
        }
    }

    private void writeScalar(Address instruction, int operand, String kind, Scalar scalar,
            Address target, String targetType) throws Exception {
        writeRow(instruction, operand, kind, Integer.toString(scalar.bitLength()),
            Long.toString(scalar.getSignedValue()),
            "0x" + Long.toUnsignedString(scalar.getUnsignedValue(), 16),
            target, targetType, null);
    }

    private void writeNumber(Address instruction, int operand, Number value,
            Address target, String targetType) throws Exception {
        writeRow(instruction, operand, "referenced-number", null, null, null,
            target, targetType, String.valueOf(value));
    }

    private void writeRow(Address instruction, int operand, String kind, String bitLength,
            String signed, String unsignedHex, Address target, String targetType, String number)
            throws Exception {
        out.write("{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"function_entry\":" + q(addr(function.getEntryPoint())) +
            ",\"instruction\":" + q(addr(instruction)) +
            ",\"operand\":" + operand +
            ",\"kind\":" + q(kind) +
            ",\"bit_length\":" + (bitLength == null ? "null" : bitLength) +
            ",\"signed_value\":" + q(signed) +
            ",\"unsigned_hex\":" + q(unsignedHex) +
            ",\"target\":" + q(addr(target)) +
            ",\"target_type\":" + q(targetType) +
            ",\"number_value\":" + q(number) + "}");
        out.newLine();
        rows++;
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
