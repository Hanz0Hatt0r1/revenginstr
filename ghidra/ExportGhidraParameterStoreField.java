import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

// Evidence-only exporter for stores from one function parameter into a field
// rooted at another parameter. It emits High-P-code structural metadata only.
public class ExportGhidraParameterStoreField extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraParameterStoreField/1";
    private static final int MAX_DEPTH = 12;

    private static final class AddressExpr {
        final Varnode base;
        final Long offset;
        final String pattern;
        AddressExpr(Varnode base, Long offset, String pattern) {
            this.base = base;
            this.offset = offset;
            this.pattern = pattern;
        }
    }

    private String cell(Object value) {
        if (value == null) return "-";
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String hex(long value) {
        return value < 0
            ? "-0x" + Long.toUnsignedString(-value, 16)
            : "0x" + Long.toUnsignedString(value, 16);
    }

    private Function resolveFunction(String token) throws Exception {
        Address address = null;
        try {
            address = toAddr(token);
        } catch (Exception ignored) {
        }
        if (address != null) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) function = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (function != null) return function;
        }

        Function exact = null;
        Function partial = null;
        int partialCount = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            String shortName = function.getName();
            String fullName = function.getName(true);
            if (token.equals(shortName) || token.equals(fullName)) {
                exact = function;
                break;
            }
            if (shortName.contains(token) || fullName.contains(token)) {
                partial = function;
                partialCount++;
            }
        }
        if (exact != null) return exact;
        if (partialCount == 1) return partial;
        if (partialCount > 1) throw new IllegalArgumentException("Ambiguous function token: " + token);
        throw new IllegalArgumentException("Function not found: " + token);
    }

    private boolean transparent(PcodeOp op) {
        if (op == null) return false;
        int code = op.getOpcode();
        return code == PcodeOp.COPY || code == PcodeOp.CAST ||
               code == PcodeOp.INDIRECT || code == PcodeOp.INT_ZEXT ||
               code == PcodeOp.INT_SEXT || code == PcodeOp.SUBPIECE;
    }

    private Varnode stripTransparent(Varnode original) {
        Varnode cursor = original;
        Set<Varnode> seen = new HashSet<Varnode>();
        for (int depth = 0; cursor != null && depth < MAX_DEPTH && seen.add(cursor); ++depth) {
            PcodeOp def = cursor.getDef();
            if (!transparent(def) || def.getNumInputs() < 1) break;
            cursor = def.getInput(0);
        }
        return cursor;
    }

    private AddressExpr decodeAddress(Varnode original) {
        Varnode cursor = stripTransparent(original);
        if (cursor == null) return new AddressExpr(null, null, "missing");
        PcodeOp def = cursor.getDef();
        if (def == null) return new AddressExpr(cursor, 0L, "direct");
        int code = def.getOpcode();
        try {
            if (code == PcodeOp.PTRSUB && def.getNumInputs() >= 2 && def.getInput(1).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return new AddressExpr(null, null, "ptrsub_base_unresolved");
                return new AddressExpr(child.base, Math.addExact(child.offset, def.getInput(1).getOffset()), "ptrsub");
            }
            if (code == PcodeOp.PTRADD && def.getNumInputs() >= 3 &&
                    def.getInput(1).isConstant() && def.getInput(2).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return new AddressExpr(null, null, "ptradd_base_unresolved");
                long delta = Math.multiplyExact(def.getInput(1).getOffset(), def.getInput(2).getOffset());
                return new AddressExpr(child.base, Math.addExact(child.offset, delta), "ptradd");
            }
            if (code == PcodeOp.INT_ADD && def.getNumInputs() >= 2) {
                Varnode base = null;
                long delta = 0L;
                if (def.getInput(1).isConstant()) {
                    base = def.getInput(0);
                    delta = def.getInput(1).getOffset();
                } else if (def.getInput(0).isConstant()) {
                    base = def.getInput(1);
                    delta = def.getInput(0).getOffset();
                }
                if (base != null) {
                    AddressExpr child = decodeAddress(base);
                    if (child.offset == null) return new AddressExpr(null, null, "int_add_base_unresolved");
                    return new AddressExpr(child.base, Math.addExact(child.offset, delta), "int_add");
                }
            }
            if (code == PcodeOp.INT_SUB && def.getNumInputs() >= 2 && def.getInput(1).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return new AddressExpr(null, null, "int_sub_base_unresolved");
                return new AddressExpr(child.base, Math.subtractExact(child.offset, def.getInput(1).getOffset()), "int_sub");
            }
        } catch (ArithmeticException ignored) {
            return new AddressExpr(null, null, "offset_overflow");
        }
        return new AddressExpr(null, null, "opaque_" + def.getMnemonic());
    }

    private int parameterIndex(HighFunction high, Varnode node) {
        if (high == null || node == null || node.getHigh() == null) return -1;
        LocalSymbolMap map = high.getLocalSymbolMap();
        if (map == null) return -1;
        HighVariable target = node.getHigh();
        for (int index = 0; index < map.getNumParams(); ++index) {
            HighSymbol symbol = map.getParamSymbol(index);
            if (symbol == null || symbol.getHighVariable() == null) continue;
            HighVariable parameter = symbol.getHighVariable();
            if (parameter == target) return index;
            if (parameter.getRepresentative() != null && target.getRepresentative() != null &&
                    parameter.getRepresentative().equals(target.getRepresentative())) return index;
        }
        return -1;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException(
            "Usage: ExportGhidraParameterStoreField.java <function-address-or-name> <output.tsv>");

        Function function = resolveFunction(args[0]);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open program");
        DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
        if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
            decompiler.dispose();
            throw new IllegalStateException("Could not decompile " + function.getEntryPoint());
        }
        HighFunction high = results.getHighFunction();

        File output = new File(args[1]);
        if (output.getParentFile() != null) output.getParentFile().mkdirs();
        int rows = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write("format\tfunction_entry\tfunction_name\tstore_address\tstore_time\t" +
                "destination_parameter_index\tdestination_offset\tdestination_pattern\t" +
                "source_parameter_index\tvalue_size\tstatus");
            out.newLine();

            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext() && !monitor.isCancelled()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.STORE || op.getNumInputs() < 3) continue;
                AddressExpr destination = decodeAddress(op.getInput(1));
                int destinationParameter = parameterIndex(high, destination.base);
                Varnode source = stripTransparent(op.getInput(2));
                int sourceParameter = parameterIndex(high, source);
                if (destinationParameter < 0 || destination.offset == null || sourceParameter < 0) continue;

                SequenceNumber sequence = op.getSeqnum();
                Varnode value = op.getInput(2);
                out.write(String.join("\t",
                    FORMAT,
                    cell(function.getEntryPoint()),
                    cell(function.getName(true)),
                    cell(sequence == null ? null : sequence.getTarget()),
                    sequence == null ? "-" : Integer.toString(sequence.getTime()),
                    Integer.toString(destinationParameter),
                    hex(destination.offset),
                    destination.pattern,
                    Integer.toString(sourceParameter),
                    value == null ? "-" : Integer.toString(value.getSize()),
                    "parameter_to_parameter_field"));
                out.newLine();
                rows++;
            }
        } finally {
            decompiler.dispose();
        }

        println("GHIDRA_PARAMETER_STORE_FIELD_FORMAT=" + FORMAT);
        println("GHIDRA_PARAMETER_STORE_FIELD_FUNCTION=" + function.getEntryPoint() + ":" + function.getName(true));
        println("GHIDRA_PARAMETER_STORE_FIELD_ROWS=" + rows);
        println("GHIDRA_PARAMETER_STORE_FIELD_OUTPUT=" + output.getAbsolutePath());
        println("GHIDRA_PARAMETER_STORE_FIELD_SEMANTIC_CLAIM=none");
    }
}
