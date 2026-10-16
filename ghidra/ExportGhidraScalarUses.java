// Export instructions that use one exact scalar value.
// Candidate inventory only: scalar equality is never semantic identity.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class ExportGhidraScalarUses extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraScalarUses/1";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraScalarUses.java <output.jsonl> <scalar-hex>"
            );
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        long target = parseScalar(args[1]);
        Listing listing = currentProgram.getListing();
        FunctionManager functions = currentProgram.getFunctionManager();
        int matchCount = 0;

        try (PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8)))) {
            InstructionIterator iterator = listing.getInstructions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = iterator.next();
                int matchingOperand = findMatchingOperand(instruction, target);
                if (matchingOperand < 0) continue;

                Function function = functions.getFunctionContaining(instruction.getAddress());
                out.println(row(instruction, function, matchingOperand, target));
                matchCount++;
            }
        }

        println("Ghidra exact scalar-use export: " + matchCount + " rows -> " + output);
    }

    private static long parseScalar(String token) {
        if (token == null) throw new IllegalArgumentException("missing scalar");
        String value = token.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        if (value.isEmpty()) throw new IllegalArgumentException("empty scalar");
        return Long.parseUnsignedLong(value, 16);
    }

    private static int findMatchingOperand(Instruction instruction, long target) {
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            Object[] objects = instruction.getOpObjects(operand);
            for (Object object : objects) {
                if (!(object instanceof Scalar)) continue;
                Scalar scalar = (Scalar) object;
                if (Long.compareUnsigned(scalar.getUnsignedValue(), target) == 0) {
                    return operand;
                }
            }
        }
        return -1;
    }

    private static String classify(Instruction instruction) {
        String mnemonic = instruction.getMnemonicString().toLowerCase();
        if (mnemonic.equals("lea")) return "address-materializer";
        if (mnemonic.startsWith("call")) return "call";
        if (mnemonic.startsWith("mov") || mnemonic.startsWith("fst") || mnemonic.startsWith("stos")) {
            return "memory-or-copy";
        }
        if (mnemonic.startsWith("add") || mnemonic.startsWith("sub") || mnemonic.startsWith("imul")) {
            return "arithmetic";
        }
        return "other";
    }

    private static String row(
            Instruction instruction,
            Function function,
            int operand,
            long target) {
        Address address = instruction.getAddress();
        String functionAddress = function == null ? null : addr(function.getEntryPoint());
        String functionName = function == null ? null : function.getName();
        String operandText = instruction.getDefaultOperandRepresentation(operand);
        return "{" +
            "\"format\":" + q(FORMAT) + "," +
            "\"program\":" + q(instruction.getProgram().getName()) + "," +
            "\"target_scalar\":" + q(hex(target)) + "," +
            "\"function_address\":" + q(functionAddress) + "," +
            "\"function_name\":" + q(functionName) + "," +
            "\"instruction_address\":" + q(addr(address)) + "," +
            "\"mnemonic\":" + q(instruction.getMnemonicString()) + "," +
            "\"text\":" + q(instruction.toString()) + "," +
            "\"matching_operand_index\":" + operand + "," +
            "\"matching_operand_text\":" + q(operandText) + "," +
            "\"usage_class\":" + q(classify(instruction)) +
            "}";
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
    }

    private static String q(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder(value.length() + 16);
        out.append('"');
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
        out.append('"');
        return out.toString();
    }
}
