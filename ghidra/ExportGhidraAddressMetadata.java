import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/** Export generic listing, memory-block, function, symbol, and raw-word metadata. */
public class ExportGhidraAddressMetadata extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraAddressMetadata/1";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraAddressMetadata.java <output.jsonl> <address> [address ...]");
        }
        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (int i = 1; i < args.length; i++) {
                monitor.checkCancelled();
                Address address = toAddr(args[i]);
                out.write(row(args[i], address));
                out.newLine();
            }
        }
        println("Exported " + (args.length - 1) + " address metadata rows -> " + output);
    }

    private String row(String requested, Address address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        Function at = currentProgram.getFunctionManager().getFunctionAt(address);
        Function containing = currentProgram.getFunctionManager().getFunctionContaining(address);
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        Data data = currentProgram.getListing().getDataAt(address);
        return "{\"format\":" + q(FORMAT) +
            ",\"program\":" + q(currentProgram.getName()) +
            ",\"requested\":" + q(requested) +
            ",\"address\":" + q(addr(address)) +
            ",\"block\":" + blockJson(block) +
            ",\"primary_symbol\":" + q(symbol == null ? null : symbol.getName()) +
            ",\"function_at\":" + functionJson(at, true) +
            ",\"function_containing\":" + functionJson(containing, false) +
            ",\"instruction_mnemonic\":" + q(instruction == null ? null : instruction.getMnemonicString()) +
            ",\"data_type\":" + q(data == null || data.getDataType() == null ? null : data.getDataType().getName()) +
            ",\"raw_u32\":" + q(rawU32(address)) + "}";
    }

    private String blockJson(MemoryBlock block) {
        if (block == null) return "null";
        return "{\"name\":" + q(block.getName()) +
            ",\"start\":" + q(addr(block.getStart())) +
            ",\"end\":" + q(addr(block.getEnd())) +
            ",\"read\":" + block.isRead() +
            ",\"write\":" + block.isWrite() +
            ",\"execute\":" + block.isExecute() + "}";
    }

    private String functionJson(Function function, boolean includeThunk) {
        if (function == null) return "null";
        String body = null;
        if (function.getBody() != null && !function.getBody().isEmpty()) {
            body = addr(function.getBody().getMinAddress()) + ".." + addr(function.getBody().getMaxAddress());
        }
        StringBuilder out = new StringBuilder("{\"entry\":")
            .append(q(addr(function.getEntryPoint())))
            .append(",\"name\":").append(q(function.getName(true)))
            .append(",\"body\":").append(q(body));
        if (includeThunk) {
            out.append(",\"is_thunk\":").append(function.isThunk())
                .append(",\"thunk_target\":").append(thunkTargetJson(function));
        }
        return out.append('}').toString();
    }

    private String thunkTargetJson(Function function) {
        if (!function.isThunk()) return "null";
        try {
            Function target = function.getThunkedFunction(true);
            return target == null ? "null" : "{\"entry\":" + q(addr(target.getEntryPoint())) +
                ",\"name\":" + q(target.getName(true)) + "}";
        } catch (Exception exc) {
            return q("<error>");
        }
    }

    private String rawU32(Address address) {
        try {
            byte[] bytes = new byte[4];
            int got = currentProgram.getMemory().getBytes(address, bytes);
            if (got != 4) return null;
            long value;
            if (currentProgram.getLanguage().isBigEndian()) {
                value = ((bytes[0] & 0xffL) << 24) | ((bytes[1] & 0xffL) << 16) |
                    ((bytes[2] & 0xffL) << 8) | (bytes[3] & 0xffL);
            } else {
                value = (bytes[0] & 0xffL) | ((bytes[1] & 0xffL) << 8) |
                    ((bytes[2] & 0xffL) << 16) | ((bytes[3] & 0xffL) << 24);
            }
            return "0x" + Long.toUnsignedString(value, 16);
        } catch (Exception exc) {
            return null;
        }
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
