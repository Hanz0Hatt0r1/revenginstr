import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
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

// Bounded High P-code candidate exporter for writes through one caller-selected field offset.
// The output contains only derived high-P-code metadata. It intentionally omits
// instruction bytes, disassembly text, decompiler C text, strings and assets.
public class ExportGhidraFieldStoreCandidates extends GhidraScript {
    private static final int MAX_ADDRESS_DEPTH = 32;

    private static final class FieldMatch {
        final PcodeOp operation;
        final Varnode base;

        FieldMatch(PcodeOp operation, Varnode base) {
            this.operation = operation;
            this.base = base;
        }
    }

    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String varnodeToken(Varnode node) {
        if (node == null) return "-";
        if (node.isConstant()) {
            return "const:0x" + Long.toUnsignedString(node.getOffset(), 16) + ":" + node.getSize();
        }
        PcodeOp definition = node.getDef();
        if (definition != null) {
            SequenceNumber sequence = definition.getSeqnum();
            return "def:" + cell(sequence.getTarget()) + ":" + sequence.getTime() + ":" + node.getSize();
        }
        String kind;
        if (node.isRegister()) {
            kind = "register";
        } else if (node.isUnique()) {
            kind = "unique";
        } else if (node.isAddress()) {
            kind = "address";
        } else {
            kind = "input";
        }
        return kind + ":" + cell(node.getAddress()) + ":" + node.getSize();
    }

    private FieldMatch findFieldAddress(
            Varnode node,
            long fieldOffset,
            int depth,
            Set<Varnode> active) {
        if (node == null || depth > MAX_ADDRESS_DEPTH || active.contains(node)) return null;
        PcodeOp definition = node.getDef();
        if (definition == null) return null;

        int opcode = definition.getOpcode();
        if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.INT_ADD) {
            for (int index = 0; index < definition.getNumInputs(); ++index) {
                Varnode input = definition.getInput(index);
                if (input != null && input.isConstant() && input.getOffset() == fieldOffset) {
                    Varnode base = null;
                    for (int other = 0; other < definition.getNumInputs(); ++other) {
                        if (other == index) continue;
                        Varnode candidate = definition.getInput(other);
                        if (candidate != null && !candidate.isConstant()) {
                            base = candidate;
                            break;
                        }
                    }
                    return new FieldMatch(definition, base);
                }
            }
        }

        Set<Varnode> nextActive = new HashSet<>(active);
        nextActive.add(node);
        for (int index = 0; index < definition.getNumInputs(); ++index) {
            Varnode input = definition.getInput(index);
            if (input == null || input.isConstant()) continue;
            FieldMatch nested = findFieldAddress(input, fieldOffset, depth + 1, nextActive);
            if (nested != null) return nested;
        }
        return null;
    }

    private boolean functionNameMatches(Function function, String[] tokens) {
        String shortName = function.getName();
        String fullName = function.getName(true);
        for (String token : tokens) {
            String trimmed = token.trim();
            if (trimmed.isEmpty()) continue;
            if (shortName.contains(trimmed) || fullName.contains(trimmed)) return true;
        }
        return false;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraFieldStoreCandidates.java <function-name-fragment;...> <field-offset> <output.tsv>");
        }

        String[] functionNameFragments = args[0].split(";");
        long fieldOffset = Long.decode(args[1]);
        if (fieldOffset < 0) throw new IllegalArgumentException("field offset must be non-negative");

        File output = new File(args[2]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open current program in decompiler");
        }

        long functionsScanned = 0;
        long rows = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write("function_entry\tfunction_name\tstore_address\tstore_time\tfield_offset_hex\taddress_opcode\taddress_op_address\taddress_op_time\tbase_token\tvalue_token\tvalue_is_constant\tvalue_constant_hex");
            out.newLine();

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (!functionNameMatches(function, functionNameFragments)) continue;
                functionsScanned++;

                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted()) continue;
                HighFunction high = results.getHighFunction();
                if (high == null) continue;

                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                while (operations.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST operation = operations.next();
                    if (operation.getOpcode() != PcodeOp.STORE || operation.getNumInputs() < 3) continue;

                    Varnode destination = operation.getInput(1);
                    FieldMatch match = findFieldAddress(
                        destination, fieldOffset, 0, new HashSet<Varnode>());
                    if (match == null) continue;

                    Varnode value = operation.getInput(2);
                    SequenceNumber storeSeq = operation.getSeqnum();
                    SequenceNumber addressSeq = match.operation.getSeqnum();
                    boolean valueConstant = value != null && value.isConstant();
                    String constantHex = valueConstant
                        ? "0x" + Long.toUnsignedString(value.getOffset(), 16)
                        : "-";

                    out.write(cell(function.getEntryPoint()) + "\t" +
                        cell(function.getName(true)) + "\t" +
                        cell(storeSeq.getTarget()) + "\t" + storeSeq.getTime() + "\t" +
                        "0x" + Long.toUnsignedString(fieldOffset, 16) + "\t" +
                        cell(match.operation.getMnemonic()) + "\t" +
                        cell(addressSeq.getTarget()) + "\t" + addressSeq.getTime() + "\t" +
                        varnodeToken(match.base) + "\t" + varnodeToken(value) + "\t" +
                        (valueConstant ? "1" : "0") + "\t" + constantHex);
                    out.newLine();
                    rows++;
                }
            }
        } finally {
            decompiler.dispose();
        }

        println("Scanned " + functionsScanned + " matching functions; exported " + rows +
            " candidate stores for field offset +0x" + Long.toUnsignedString(fieldOffset, 16) +
            " -> " + output);
    }
}
