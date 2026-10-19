import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

// Evidence-only exporter for stores from one function parameter into a field
// rooted at another parameter. It emits High-P-code structural metadata only.
public class ExportGhidraParameterStoreField extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraParameterStoreField/1";
    private static final String MEMORY_ACCESS_FORMAT = "REVENGINSTR.GhidraMemoryStoreAccess/1";
    private static final int MAX_DEPTH = 12;
    private static final int MAX_FUNCTIONS = 256;

    private static final class OperationRef {
        final String address;
        final int time;
        final String opcode;
        OperationRef(String address, int time, String opcode) {
            this.address = address;
            this.time = time;
            this.opcode = opcode;
        }
    }

    private static final class AddressExpr {
        final Varnode base;
        final Long offset;
        final String pattern;
        final List<OperationRef> operations;
        AddressExpr(Varnode base, Long offset, String pattern, List<OperationRef> operations) {
            this.base = base;
            this.offset = offset;
            this.pattern = pattern;
            this.operations = operations;
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

    private Function resolveFunctionEntry(String token) throws Exception {
        Address address;
        try {
            address = toAddr(token);
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid function entry: " + token);
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) throw new IllegalArgumentException("No function at entry: " + token);
        return function;
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
        Varnode cursor = original;
        List<OperationRef> transparentOperations = new ArrayList<OperationRef>();
        Set<Varnode> seen = new HashSet<Varnode>();
        for (int depth = 0; cursor != null && depth < MAX_DEPTH && seen.add(cursor); ++depth) {
            PcodeOp definition = cursor.getDef();
            if (!transparent(definition) || definition.getNumInputs() < 1) break;
            OperationRef reference = operationRef(definition);
            if (reference != null) transparentOperations.add(reference);
            cursor = definition.getInput(0);
        }
        AddressExpr expression = decodeAddressCore(cursor);
        if (!transparentOperations.isEmpty()) {
            List<OperationRef> operations = new ArrayList<OperationRef>(expression.operations);
            for (int i = transparentOperations.size() - 1; i >= 0; --i) operations.add(transparentOperations.get(i));
            return new AddressExpr(expression.base, expression.offset, expression.pattern, operations);
        }
        return expression;
    }

    private AddressExpr decodeAddressCore(Varnode cursor) {
        if (cursor == null) return new AddressExpr(null, null, "missing", new ArrayList<OperationRef>());
        PcodeOp def = cursor.getDef();
        if (def == null) return new AddressExpr(cursor, 0L, "direct", new ArrayList<OperationRef>());
        int code = def.getOpcode();
        try {
            if (code == PcodeOp.PTRSUB && def.getNumInputs() >= 2 && def.getInput(1).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return withOperation(null, null, "ptrsub_base_unresolved", child.operations, def);
                return withOperation(child.base, Math.addExact(child.offset, def.getInput(1).getOffset()), "ptrsub", child.operations, def);
            }
            if (code == PcodeOp.PTRADD && def.getNumInputs() >= 3 &&
                    def.getInput(1).isConstant() && def.getInput(2).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return withOperation(null, null, "ptradd_base_unresolved", child.operations, def);
                long delta = Math.multiplyExact(def.getInput(1).getOffset(), def.getInput(2).getOffset());
                return withOperation(child.base, Math.addExact(child.offset, delta), "ptradd", child.operations, def);
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
                    if (child.offset == null) return withOperation(null, null, "int_add_base_unresolved", child.operations, def);
                    return withOperation(child.base, Math.addExact(child.offset, delta), "int_add", child.operations, def);
                }
            }
            if (code == PcodeOp.INT_SUB && def.getNumInputs() >= 2 && def.getInput(1).isConstant()) {
                AddressExpr child = decodeAddress(def.getInput(0));
                if (child.offset == null) return withOperation(null, null, "int_sub_base_unresolved", child.operations, def);
                return withOperation(child.base, Math.subtractExact(child.offset, def.getInput(1).getOffset()), "int_sub", child.operations, def);
            }
        } catch (ArithmeticException ignored) {
            return withOperation(null, null, "offset_overflow", new ArrayList<OperationRef>(), def);
        }
        return withOperation(null, null, "opaque_" + def.getMnemonic(), new ArrayList<OperationRef>(), def);
    }

    private AddressExpr withOperation(
            Varnode base, Long offset, String pattern, List<OperationRef> childOperations, PcodeOp operation) {
        List<OperationRef> operations = new ArrayList<OperationRef>(childOperations);
        OperationRef reference = operationRef(operation);
        if (reference != null) operations.add(reference);
        return new AddressExpr(base, offset, pattern, operations);
    }

    private OperationRef operationRef(PcodeOp operation) {
        if (operation == null || operation.getSeqnum() == null || operation.getSeqnum().getTarget() == null) {
            throw new IllegalStateException("Address expression operation has no P-code sequence identity");
        }
        SequenceNumber sequence = operation.getSeqnum();
        return new OperationRef(cell(sequence.getTarget()), sequence.getTime(), operation.getMnemonic());
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

    private String valueToken(Varnode node) {
        if (node == null) return "-";
        PcodeOp def = node.getDef();
        if (def != null) {
            SequenceNumber sequence = def.getSeqnum();
            return "def:" + def.getMnemonic() + "@" + cell(sequence.getTarget()) + ":" +
                sequence.getTime() + ":" + node.getSize();
        }
        return "input:" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private String varnodeToken(Varnode node) {
        if (node == null) return "-";
        if (node.isConstant()) {
            return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        }
        PcodeOp definition = node.getDef();
        if (definition != null && definition.getSeqnum() != null) {
            SequenceNumber sequence = definition.getSeqnum();
            return "def:" + cell(sequence.getTarget()) + ":" + sequence.getTime() + ":" + node.getSize();
        }
        String kind = node.isRegister() ? "register" : node.isUnique() ? "unique" : node.isAddress() ? "address" : "input";
        return kind + ":" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private AddressSpace memoryAddressSpace(PcodeOp operation) {
        if (operation == null || operation.getOpcode() != PcodeOp.STORE || operation.getNumInputs() < 1) return null;
        Varnode spaceId = operation.getInput(0);
        if (spaceId == null || !spaceId.isConstant()) return null;
        long offset = spaceId.getOffset();
        if (offset < 0 || offset > Integer.MAX_VALUE) return null;
        try {
            return currentProgram.getAddressFactory().getAddressSpace((int) offset);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private String quote(String value) {
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
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private String addressOperationsJson(List<OperationRef> operations) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < operations.size(); index++) {
            if (index > 0) out.append(',');
            OperationRef operation = operations.get(index);
            out.append("{\"address\":").append(quote(operation.address))
                .append(",\"time\":").append(operation.time)
                .append(",\"opcode\":").append(quote(operation.opcode)).append('}');
        }
        return out.append(']').toString();
    }

    private String memoryStoreAccessJson(
            String programId, Function function, PcodeOp operation,
            AddressExpr destination, int rootParameter) {
        SequenceNumber sequence = operation.getSeqnum();
        if (sequence == null || sequence.getTarget() == null) {
            throw new IllegalStateException("STORE has no P-code sequence identity");
        }
        AddressSpace space = memoryAddressSpace(operation);
        AddressSpace physical = space == null ? null : space.getPhysicalSpace();
        Varnode pointer = operation.getNumInputs() >= 2 ? operation.getInput(1) : null;
        Varnode value = operation.getNumInputs() >= 3 ? operation.getInput(2) : null;
        Integer width = value == null || value.getSize() < 1 ? null : value.getSize();
        Integer pointerWidth = space == null || space.getPointerSize() < 1 ? null : space.getPointerSize();
        Integer spaceSizeBits = space == null || space.getSize() < 1 ? null : space.getSize();
        Integer addressableUnitBytes = space == null || space.getAddressableUnitSize() < 1
            ? null : space.getAddressableUnitSize();
        boolean resolved = rootParameter >= 0 && destination.offset != null && width != null &&
            space != null && pointerWidth != null && spaceSizeBits != null && addressableUnitBytes != null;
        StringBuilder out = new StringBuilder(384)
            .append("{\"format\":").append(quote(MEMORY_ACCESS_FORMAT))
            .append(",\"program_id\":").append(quote(programId))
            .append(",\"function_entry\":").append(quote(function.getEntryPoint().toString()))
            .append(",\"address\":").append(quote(sequence.getTarget().toString()))
            .append(",\"time\":").append(sequence.getTime())
            .append(",\"opcode\":\"STORE\"")
            .append(",\"memory_space\":").append(space == null ? "null" : quote(space.getName()))
            .append(",\"memory_physical_space\":").append(physical == null ? "null" : quote(physical.getName()))
            .append(",\"memory_width_bytes\":").append(width == null ? "null" : width)
            .append(",\"memory_pointer_width_bytes\":").append(pointerWidth == null ? "null" : pointerWidth)
            .append(",\"memory_space_size_bits\":").append(spaceSizeBits == null ? "null" : spaceSizeBits)
            .append(",\"memory_addressable_unit_bytes\":").append(addressableUnitBytes == null ? "null" : addressableUnitBytes)
            .append(",\"pointer_token\":").append(quote(varnodeToken(pointer)))
            .append(",\"root_parameter_index\":").append(rootParameter < 0 ? "null" : Integer.toString(rootParameter))
            .append(",\"offset_bytes\":").append(destination.offset == null ? "null" : Long.toString(destination.offset))
            .append(",\"location_status\":").append(quote(resolved ? "parameter_rooted_constant_offset" : "unresolved"))
            .append(",\"destination_pattern\":").append(quote(destination.pattern))
            .append(",\"address_expression_ops\":").append(addressOperationsJson(destination.operations))
            .append('}');
        return out.toString();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException(
            "Usage: ExportGhidraParameterStoreField.java <function-address-or-name> <stores.tsv> " +
            "[--function-entry <entry> ...] [--load-output <loads.tsv>] " +
            "[--memory-access-output <stores.jsonl> --program-id <id>]");
        List<Function> functions = new ArrayList<Function>();
        Set<String> functionEntries = new HashSet<String>();
        Function firstFunction = resolveFunction(args[0]);
        functions.add(firstFunction);
        functionEntries.add(firstFunction.getEntryPoint().toString());
        File storeOutput = new File(args[1]);
        File loadOutput = null;
        File memoryAccessOutput = null;
        String programId = null;
        for (int i = 2; i < args.length; i++) {
            String option = args[i];
            if ("--function-entry".equals(option) || "--load-output".equals(option) ||
                    "--memory-access-output".equals(option) || "--program-id".equals(option)) {
                if (i + 1 >= args.length) throw new IllegalArgumentException("Missing value for " + option);
                String value = args[++i];
                if ("--function-entry".equals(option)) {
                    Function function = resolveFunctionEntry(value);
                    String entry = function.getEntryPoint().toString();
                    if (!functionEntries.add(entry)) {
                        throw new IllegalArgumentException("duplicate function entry: " + entry);
                    }
                    functions.add(function);
                    if (functions.size() > MAX_FUNCTIONS) {
                        throw new IllegalArgumentException("function batch exceeds " + MAX_FUNCTIONS);
                    }
                } else if ("--load-output".equals(option)) {
                    if (loadOutput != null) throw new IllegalArgumentException("Duplicate --load-output");
                    loadOutput = new File(value);
                } else if ("--memory-access-output".equals(option)) {
                    if (memoryAccessOutput != null) throw new IllegalArgumentException("Duplicate --memory-access-output");
                    memoryAccessOutput = new File(value);
                } else {
                    if (programId != null) throw new IllegalArgumentException("Duplicate --program-id");
                    programId = value;
                }
            } else {
                throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (memoryAccessOutput != null && (programId == null || programId.isEmpty())) {
            throw new IllegalArgumentException("--memory-access-output requires a non-empty --program-id");
        }
        if (memoryAccessOutput == null && programId != null) {
            throw new IllegalArgumentException("--program-id requires --memory-access-output");
        }
        Set<String> outputPaths = new HashSet<String>();
        outputPaths.add(storeOutput.getCanonicalPath());
        if (loadOutput != null && !outputPaths.add(loadOutput.getCanonicalPath()))
            throw new IllegalArgumentException("output paths must be different files");
        if (memoryAccessOutput != null && !outputPaths.add(memoryAccessOutput.getCanonicalPath()))
            throw new IllegalArgumentException("output paths must be different files");
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.toggleCCode(false) || !decompiler.toggleSyntaxTree(true)) {
            throw new IllegalStateException("Could not configure P-code-only decompilation");
        }
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open program");

        if (storeOutput.getParentFile() != null) storeOutput.getParentFile().mkdirs();
        if (loadOutput != null && loadOutput.getParentFile() != null) loadOutput.getParentFile().mkdirs();
        if (memoryAccessOutput != null && memoryAccessOutput.getParentFile() != null) memoryAccessOutput.getParentFile().mkdirs();
        int storeRows = 0;
        int loadRows = 0;
        int memoryAccessRows = 0;
        int completedFunctions = 0;
        try (BufferedWriter storeOut = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(storeOutput), StandardCharsets.UTF_8));
             BufferedWriter loadOut = loadOutput == null ? null : new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(loadOutput), StandardCharsets.UTF_8));
             BufferedWriter memoryAccessOut = memoryAccessOutput == null ? null : new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(memoryAccessOutput), StandardCharsets.UTF_8))) {
            storeOut.write("format\tfunction_entry\tfunction_name\tstore_address\tstore_time\t" +
                "destination_parameter_index\tdestination_offset\tdestination_pattern\t" +
                "source_parameter_index\tvalue_size\tstatus");
            storeOut.newLine();
            if (loadOut != null) {
                loadOut.write("format\tfunction_entry\tfunction_name\tload_address\tload_time\t" +
                    "base_parameter_index\tfield_offset\taddress_pattern\tvalue_size\tvalue_token\tstatus");
                loadOut.newLine();
            }

            for (Function function : functions) {
                if (monitor.isCancelled()) throw new IllegalStateException("Export cancelled before all functions were written");
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) {
                    throw new IllegalStateException("Could not decompile " + function.getEntryPoint());
                }
                HighFunction high = results.getHighFunction();
                int functionStoreRows = 0;
                int functionLoadRows = 0;
                int functionMemoryAccessRows = 0;
                Iterator<PcodeOpAST> ops = high.getPcodeOps();
                while (ops.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST op = ops.next();
                    if (loadOut != null && op.getOpcode() == PcodeOp.LOAD && op.getNumInputs() >= 2) {
                        AddressExpr address = decodeAddress(op.getInput(1));
                        int baseParameter = parameterIndex(high, address.base);
                        Varnode value = op.getOutput();
                        if (baseParameter >= 0 && address.offset != null && value != null) {
                            SequenceNumber sequence = op.getSeqnum();
                            loadOut.write(String.join("\t",
                                "REVENGINSTR.GhidraParameterLoadField/1",
                                cell(function.getEntryPoint()),
                                cell(function.getName(true)),
                                cell(sequence == null ? null : sequence.getTarget()),
                                sequence == null ? "-" : Integer.toString(sequence.getTime()),
                                Integer.toString(baseParameter),
                                hex(address.offset),
                                address.pattern,
                                Integer.toString(value.getSize()),
                                valueToken(value),
                                "parameter_field_load"));
                            loadOut.newLine();
                            loadRows++;
                            functionLoadRows++;
                        }
                    }
                    if (op.getOpcode() != PcodeOp.STORE) continue;
                    AddressExpr destination = op.getNumInputs() >= 2
                        ? decodeAddress(op.getInput(1)) : decodeAddress(null);
                    int destinationParameter = parameterIndex(high, destination.base);
                    if (memoryAccessOut != null) {
                        memoryAccessOut.write(memoryStoreAccessJson(
                            programId, function, op, destination, destinationParameter));
                        memoryAccessOut.newLine();
                        memoryAccessRows++;
                        functionMemoryAccessRows++;
                    }
                    if (op.getNumInputs() < 3) continue;
                    Varnode source = stripTransparent(op.getInput(2));
                    int sourceParameter = parameterIndex(high, source);
                    if (destinationParameter < 0 || destination.offset == null || sourceParameter < 0) continue;

                    SequenceNumber sequence = op.getSeqnum();
                    Varnode value = op.getInput(2);
                    storeOut.write(String.join("\t",
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
                    storeOut.newLine();
                    storeRows++;
                    functionStoreRows++;
                }
                if (monitor.isCancelled()) {
                    throw new IllegalStateException("Export cancelled before all P-code operations were written");
                }
                completedFunctions++;
                println("GHIDRA_PARAMETER_STORE_FIELD_FUNCTION=" +
                    function.getEntryPoint() + ":" + function.getName(true));
                println("GHIDRA_PARAMETER_STORE_FIELD_FUNCTION_ROWS=" + functionStoreRows);
                println("GHIDRA_PARAMETER_LOAD_FIELD_FUNCTION_ROWS=" + functionLoadRows);
                println("GHIDRA_MEMORY_STORE_ACCESS_FUNCTION_ROWS=" + functionMemoryAccessRows);
            }
        } finally {
            decompiler.dispose();
        }

        println("GHIDRA_PARAMETER_STORE_FIELD_FORMAT=" + FORMAT);
        println("GHIDRA_PARAMETER_STORE_FIELD_FUNCTIONS=" + completedFunctions);
        println("GHIDRA_PARAMETER_STORE_FIELD_ROWS=" + storeRows);
        println("GHIDRA_PARAMETER_STORE_FIELD_OUTPUT=" + storeOutput.getAbsolutePath());
        if (loadOutput != null) {
            println("GHIDRA_PARAMETER_LOAD_FIELD_FORMAT=REVENGINSTR.GhidraParameterLoadField/1");
            println("GHIDRA_PARAMETER_LOAD_FIELD_ROWS=" + loadRows);
            println("GHIDRA_PARAMETER_LOAD_FIELD_OUTPUT=" + loadOutput.getAbsolutePath());
        }
        if (memoryAccessOutput != null) {
            println("GHIDRA_MEMORY_STORE_ACCESS_FORMAT=" + MEMORY_ACCESS_FORMAT);
            println("GHIDRA_MEMORY_STORE_ACCESS_ROWS=" + memoryAccessRows);
            println("GHIDRA_MEMORY_STORE_ACCESS_OUTPUT=" + memoryAccessOutput.getAbsolutePath());
        }
        println("GHIDRA_PARAMETER_STORE_FIELD_SEMANTIC_CLAIM=none");
    }
}
