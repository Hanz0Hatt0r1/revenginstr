import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Export bounded raw pointer-table slots from an analyzed Ghidra program. */
public class ExportGhidraPointerTableSlots extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraPointerTableSlots/1";
    private static final int MAX_SLOTS = 4096;
    private static final int MAX_TABLES = 64;

    private static final class TableRequest {
        final Address address;
        final int slots;

        TableRequest(Address address, int slots) {
            this.address = address;
            this.slots = slots;
        }
    }

    private long parseHexAddress(String token) {
        String value = token.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
        if (value.isEmpty()) throw new IllegalArgumentException("empty address");
        return Long.parseUnsignedLong(value, 16);
    }

    private Address address(long offset) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        if (Long.compareUnsigned(offset, space.getMaxAddress().getOffset()) > 0) return null;
        try {
            return space.getAddress(offset);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private String bytes(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte b : value) result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return result.toString();
    }

    private String q(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 0x20) result.append(String.format(Locale.ROOT, "\\u%04x", (int)c));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }

    private String functionJson(Function function) {
        if (function == null) return "null";
        return "{\"entry\":" + q(hex(function.getEntryPoint().getOffset())) +
            ",\"name\":" + q(function.getName(true)) +
            ",\"signature\":" + q(String.valueOf(function.getSignature())) + "}";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4 || (args.length - 2) % 2 != 0) {
            throw new IllegalArgumentException(
                "usage: ExportGhidraPointerTableSlots.java <output.jsonl> <program-id> <table-address> <slot-count> [table-address slot-count ...]");
        }
        String programId = args[1].trim();
        if (programId.isEmpty()) throw new IllegalArgumentException("program-id must not be empty");

        int pointerSize = currentProgram.getDefaultPointerSize();
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalStateException("unsupported default pointer size: " + pointerSize);
        }

        List<TableRequest> tables = new ArrayList<>();
        for (int i = 2; i < args.length; i += 2) {
            if (tables.size() >= MAX_TABLES) throw new IllegalArgumentException("table limit exceeded");
            long baseOffset = parseHexAddress(args[i]);
            Address base = address(baseOffset);
            if (base == null) throw new IllegalArgumentException("table address is outside the default address space: " + args[i]);
            int slots = Integer.parseInt(args[i + 1]);
            if (slots < 1 || slots > MAX_SLOTS) {
                throw new IllegalArgumentException("slot-count must be in range 1.." + MAX_SLOTS);
            }
            tables.add(new TableRequest(base, slots));
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        Memory memory = currentProgram.getMemory();
        FunctionManager functions = currentProgram.getFunctionManager();
        String languageId = currentProgram.getLanguageID().toString();
        String imageBase = hex(currentProgram.getImageBase().getOffset());
        long rows = 0;
        long functionEntries = 0;

        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (int tableIndex = 0; tableIndex < tables.size(); tableIndex++) {
                TableRequest table = tables.get(tableIndex);
                for (int slotIndex = 0; slotIndex < table.slots && !monitor.isCancelled(); slotIndex++) {
                    monitor.checkCancelled();
                    long offset = (long)slotIndex * pointerSize;
                    Address slotAddress;
                    try {
                        slotAddress = table.address.addNoWrap(offset);
                    } catch (RuntimeException ex) {
                        slotAddress = null;
                    }

                    byte[] rawBytes = null;
                    Long rawValue = null;
                    Address targetAddress = null;
                    Function targetFunction = null;
                    String status;
                    if (slotAddress == null || !memory.contains(slotAddress)) {
                        status = "unmapped_slot";
                    } else {
                        rawBytes = new byte[pointerSize];
                        try {
                            if (memory.getBytes(slotAddress, rawBytes) != pointerSize) {
                                status = "unreadable_slot";
                                rawBytes = null;
                            } else {
                                long value = pointerSize == 4
                                    ? Integer.toUnsignedLong(memory.getInt(slotAddress))
                                    : memory.getLong(slotAddress);
                                rawValue = value;
                                if (value == 0) {
                                    status = "null_pointer";
                                } else {
                                    targetAddress = address(value);
                                    if (targetAddress == null) {
                                        status = "invalid_target_address";
                                    } else if (!memory.contains(targetAddress)) {
                                        status = "unmapped_target";
                                    } else {
                                        targetFunction = functions.getFunctionAt(targetAddress);
                                        status = targetFunction == null ? "mapped_non_function" : "function_entry";
                                        if (targetFunction != null) functionEntries++;
                                    }
                                }
                            }
                        } catch (MemoryAccessException ex) {
                            status = "unreadable_slot";
                            rawBytes = null;
                            rawValue = null;
                        }
                    }

                    String json = "{\"format\":" + q(FORMAT) +
                        ",\"program_id\":" + q(programId) +
                        ",\"language_id\":" + q(languageId) +
                        ",\"image_base\":" + q(imageBase) +
                        ",\"pointer_size_bytes\":" + pointerSize +
                        ",\"table_index\":" + tableIndex +
                        ",\"table_address\":" + q(hex(table.address.getOffset())) +
                        ",\"requested_slot_count\":" + table.slots +
                        ",\"slot_index\":" + slotIndex +
                        ",\"slot_offset_bytes\":" + offset +
                        ",\"slot_address\":" + q(slotAddress == null ? null : hex(slotAddress.getOffset())) +
                        ",\"raw_bytes\":" + q(rawBytes == null ? null : bytes(rawBytes)) +
                        ",\"pointer_value\":" + q(rawValue == null ? null : hex(rawValue)) +
                        ",\"target_address\":" + q(targetAddress == null ? null : hex(targetAddress.getOffset())) +
                        ",\"target_function\":" + functionJson(targetFunction) +
                        ",\"status\":" + q(status) + "}";
                    out.write(json);
                    out.newLine();
                    rows++;
                }
            }
        }

        println("POINTER_TABLE_SLOTS_FORMAT=" + FORMAT);
        println("POINTER_TABLE_COUNT=" + tables.size());
        println("POINTER_TABLE_ROWS=" + rows);
        println("POINTER_TABLE_FUNCTION_ENTRIES=" + functionEntries);
        println("POINTER_TABLE_OUTPUT=" + output.getAbsolutePath());
    }
}
