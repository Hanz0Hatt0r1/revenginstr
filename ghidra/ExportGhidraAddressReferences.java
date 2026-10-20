import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/** Export generic data and direct-reference evidence for caller-selected addresses. */
public class ExportGhidraAddressReferences extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraAddressReferences/1";
    private Listing listing;
    private Memory memory;
    private FunctionManager functions;
    private ReferenceManager references;
    private SymbolTable symbols;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraAddressReferences.java <output.jsonl> <address> [address ...]");
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        functions = currentProgram.getFunctionManager();
        references = currentProgram.getReferenceManager();
        symbols = currentProgram.getSymbolTable();
        List<String> missing = new ArrayList<>();

        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (int i = 1; i < args.length; i++) {
                monitor.checkCancelled();
                String token = args[i];
                Address address = parseTargetAddress(token);
                if (address == null || !memory.contains(address)) {
                    missing.add(token);
                    out.write(missingRow(token, address));
                } else {
                    out.write(addressRow(token, address));
                }
                out.newLine();
            }
        }

        if (!missing.isEmpty()) {
            throw new IllegalStateException("requested addresses not found in memory: " +
                String.join(", ", missing));
        }
        println("GHIDRA_ADDRESS_REFERENCES_FORMAT=" + FORMAT);
        println("GHIDRA_ADDRESS_REFERENCES_ROWS=" + (args.length - 1));
        println("Ghidra address-reference export -> " + output);
    }

    private Address parseTargetAddress(String token) {
        if (token == null) return null;
        String value = token.trim();
        if (value.startsWith("DAT_") || value.startsWith("dat_")) value = value.substring(4);
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        try {
            return toAddr(Long.parseUnsignedLong(value, 16));
        } catch (RuntimeException exc) {
            return null;
        }
    }

    private String addressRow(String requested, Address address) throws Exception {
        Data data = listing.getDataAt(address);
        MemoryBlock block = memory.getBlock(address);
        Symbol primary = symbols.getPrimarySymbol(address);
        LinkedHashSet<String> functionAddresses = new LinkedHashSet<>();
        StringBuilder refsJson = new StringBuilder("[");
        boolean first = true;
        int refCount = 0;

        ReferenceIterator iterator = references.getReferencesTo(address);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Reference ref = iterator.next();
            refCount++;
            Address from = ref.getFromAddress();
            Function function = from == null ? null : functions.getFunctionContaining(from);
            Instruction instruction = from == null ? null : listing.getInstructionAt(from);
            String functionAddress = function == null ? null : addr(function.getEntryPoint());
            if (functionAddress != null) functionAddresses.add(functionAddress);

            if (!first) refsJson.append(',');
            first = false;
            refsJson.append("{\"from\":").append(q(addr(from)))
                .append(",\"type\":").append(q(ref.getReferenceType().getName()))
                .append(",\"source\":").append(q(ref.getSource().toString()))
                .append(",\"operand_index\":").append(ref.getOperandIndex())
                .append(",\"primary\":").append(ref.isPrimary())
                .append(",\"function_address\":").append(q(functionAddress))
                .append(",\"function_name\":").append(q(function == null ? null : function.getName()))
                .append(",\"instruction\":").append(q(instruction == null ? null : instruction.toString()))
                .append('}');
        }
        refsJson.append(']');

        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"executable_md5\":" + q(currentProgram.getExecutableMD5()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(address)) +
            ",\"found\":true" +
            ",\"target_block\":" + q(block == null ? null : block.getName()) +
            ",\"primary_symbol\":" + q(primary == null ? null : primary.getName(true)) +
            ",\"data_type\":" + q(data == null ? null : data.getDataType().getDisplayName()) +
            ",\"data_length\":" + (data == null ? 0 : data.getLength()) +
            ",\"reference_count\":" + refCount +
            ",\"function_addresses\":" + stringArray(functionAddresses) +
            ",\"references\":" + refsJson + "}";
    }

    private String missingRow(String requested, Address address) {
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"executable_md5\":" + q(currentProgram.getExecutableMD5()) +
            ",\"requested\":" + q(requested) +
            ",\"resolved_address\":" + q(addr(address)) +
            ",\"found\":false,\"target_block\":null,\"primary_symbol\":null" +
            ",\"data_type\":null,\"data_length\":0,\"reference_count\":0" +
            ",\"function_addresses\":[],\"references\":[]}";
    }

    private static String addr(Address address) {
        return address == null ? null : "0x" + address.toString(false, false);
    }

    private static String stringArray(Iterable<String> values) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) out.append(',');
            first = false;
            out.append(q(value));
        }
        return out.append(']').toString();
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
