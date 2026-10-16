import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

// Export conservative ARM32 Itanium primary-vtable slot pointers from analyzed
// program memory. Starting at the primary address point (+8), only the contiguous
// function-pointer prefix is emitted. The first zero/unreadable/non-function word
// terminates that vtable. Reads metadata/pointers only; never modifies the program.
public class ExportArm32ItaniumVtableSlots extends GhidraScript {
    private static final int ADDRESS_POINT_DELTA = 8;
    private static final int POINTER_SIZE = 4;
    private static final long DEFAULT_MAX_SLOT_OFFSET = 0x400L;
    private static final long UINT32_MASK = 0xffffffffL;

    private static final class VtableSymbol {
        final Address start;
        final String name;
        final boolean primary;

        VtableSymbol(Address start, String name, boolean primary) {
            this.start = start;
            this.name = name;
            this.primary = primary;
        }
    }

    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String hex(long value) {
        return String.format(Locale.ROOT, "0x%x", value);
    }

    private boolean isVtableName(String name) {
        String leaf = name;
        int ns = leaf.lastIndexOf("::");
        if (ns >= 0) leaf = leaf.substring(ns + 2);
        if (leaf.startsWith("_ZTV")) return true;
        String low = name.toLowerCase(Locale.ROOT);
        return low.contains("vtable for ") || low.contains("construction vtable for ");
    }

    private Address checkedAddress(long offset) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long maxOffset = space.getMaxAddress().getOffset();
        if (Long.compareUnsigned(offset, maxOffset) > 0) return null;
        try {
            return space.getAddress(offset);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private Long checkedBiasedOffset(long canonical, long imageBase) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long maxOffset = space.getMaxAddress().getOffset();
        if (Long.compareUnsigned(imageBase, maxOffset) > 0) return null;
        long remaining = maxOffset - imageBase;
        if (Long.compareUnsigned(canonical, remaining) > 0) return null;
        return imageBase + canonical;
    }

    private Function resolveFunction(FunctionManager functions, long rawValue, long imageBase) {
        long canonical = (rawValue & UINT32_MASK) & ~1L;

        Address directAddress = checkedAddress(canonical);
        if (directAddress != null) {
            Function direct = functions.getFunctionAt(directAddress);
            if (direct != null) return direct;
        }

        Long biased = checkedBiasedOffset(canonical, imageBase);
        if (biased != null) {
            Address biasedAddress = checkedAddress(biased.longValue());
            if (biasedAddress != null) {
                Function viaImageBase = functions.getFunctionAt(biasedAddress);
                if (viaImageBase != null) return viaImageBase;
            }
        }
        return null;
    }

    private String resolutionMode(Function target, long rawValue, long imageBase) {
        long canonical = (rawValue & UINT32_MASK) & ~1L;
        long targetOffset = target.getEntryPoint().getOffset();
        if (targetOffset == canonical) return "direct_ghidra_address";
        Long biased = checkedBiasedOffset(canonical, imageBase);
        if (biased != null && targetOffset == biased.longValue()) {
            return "image_base_plus_module_offset";
        }
        return "unexpected";
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException(
                "usage: ExportArm32ItaniumVtableSlots.java <output.tsv.gz> [max-slot-offset]");
        }

        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        long maxSlotOffset = args.length == 2 ? Long.decode(args[1]) : DEFAULT_MAX_SLOT_OFFSET;
        if (maxSlotOffset < 0 || maxSlotOffset > 0x4000L || (maxSlotOffset % POINTER_SIZE) != 0) {
            throw new IllegalArgumentException(
                "max-slot-offset must be 4-byte aligned and in range 0..0x4000");
        }

        Map<Long, VtableSymbol> byStart = new LinkedHashMap<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();
            String name = symbol.getName(true);
            if (!isVtableName(name)) continue;
            long start = symbol.getAddress().getOffset();
            VtableSymbol previous = byStart.get(start);
            VtableSymbol candidate = new VtableSymbol(symbol.getAddress(), name, symbol.isPrimary());
            if (previous == null || (!previous.primary && candidate.primary)) {
                byStart.put(start, candidate);
            }
        }

        List<VtableSymbol> vtables = new ArrayList<>(byStart.values());
        vtables.sort(Comparator.comparingLong(v -> v.start.getOffset()));

        Memory memory = currentProgram.getMemory();
        FunctionManager functions = currentProgram.getFunctionManager();
        long imageBase = currentProgram.getImageBase().getOffset();
        long rows = 0;
        long resolved = 0;
        long stoppedZero = 0;
        long stoppedNonFunction = 0;
        long stoppedUnreadable = 0;
        long stoppedMemoryBoundary = 0;

        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new GZIPOutputStream(new FileOutputStream(output)), StandardCharsets.UTF_8))) {
            out.write("vtable_symbol_start\tvtable_symbol_name\taddress_point\tslot_offset\t" +
                "slot_address\traw_value\ttarget_thumb\ttarget_entry\ttarget_name\t" +
                "target_signature\tresolution_mode\tnext_vtable_symbol_start");
            out.newLine();

            for (int i = 0; i < vtables.size() && !monitor.isCancelled(); i++) {
                VtableSymbol vtable = vtables.get(i);
                Address addressPoint = vtable.start.add(ADDRESS_POINT_DELTA);
                long nextStart = (i + 1 < vtables.size())
                    ? vtables.get(i + 1).start.getOffset()
                    : Long.MAX_VALUE;

                for (long slotOffset = 0; slotOffset <= maxSlotOffset; slotOffset += POINTER_SIZE) {
                    long slotLong = addressPoint.getOffset() + slotOffset;
                    if (Long.compareUnsigned(slotLong, nextStart) >= 0) break;
                    Address slotAddress = checkedAddress(slotLong);
                    if (slotAddress == null || !memory.contains(slotAddress)) {
                        stoppedMemoryBoundary++;
                        break;
                    }

                    final long rawValue;
                    try {
                        rawValue = Integer.toUnsignedLong(memory.getInt(slotAddress));
                    } catch (MemoryAccessException ex) {
                        stoppedUnreadable++;
                        break;
                    }
                    if (rawValue == 0) {
                        stoppedZero++;
                        break;
                    }

                    Function target = resolveFunction(functions, rawValue, imageBase);
                    if (target == null) {
                        stoppedNonFunction++;
                        break;
                    }

                    boolean thumb = (rawValue & 1L) != 0;
                    String mode = resolutionMode(target, rawValue, imageBase);
                    out.write(hex(vtable.start.getOffset()) + "\t" + cell(vtable.name) + "\t" +
                        hex(addressPoint.getOffset()) + "\t" + hex(slotOffset) + "\t" +
                        hex(slotLong) + "\t" + hex(rawValue) + "\t" + thumb + "\t" +
                        cell(target.getEntryPoint()) + "\t" + cell(target.getName(true)) + "\t" +
                        cell(target.getSignature()) + "\t" + mode + "\t" +
                        (nextStart == Long.MAX_VALUE ? "-" : hex(nextStart)));
                    out.newLine();
                    rows++;
                    resolved++;
                }
            }
        }

        println("VTABLE_SLOT_FORMAT=REVENGINSTR.GhidraArm32ItaniumVtableSlots/1");
        println("VTABLE_SYMBOLS=" + vtables.size());
        println("VTABLE_SLOT_ROWS=" + rows);
        println("VTABLE_SLOT_RESOLVED_FUNCTIONS=" + resolved);
        println("VTABLE_SLOT_STOP_ZERO=" + stoppedZero);
        println("VTABLE_SLOT_STOP_NON_FUNCTION=" + stoppedNonFunction);
        println("VTABLE_SLOT_STOP_UNREADABLE=" + stoppedUnreadable);
        println("VTABLE_SLOT_STOP_MEMORY_BOUNDARY=" + stoppedMemoryBoundary);
        println("VTABLE_SLOT_IMAGE_BASE=" + hex(imageBase));
        println("VTABLE_SLOT_MAX_OFFSET=" + hex(maxSlotOffset));
        println("VTABLE_SLOT_OUTPUT=" + output.getAbsolutePath());
    }
}
