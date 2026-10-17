import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
import java.util.Iterator;

// Focused clean-room data-flow export for one analyzed function. The output is
// high P-code metadata only: operation kind/address, stable varnode dependency
// tokens and resolved call targets. It intentionally omits instruction bytes,
// assembly/disassembly text, decompiler C text, strings and source assets.
public class ExportFunctionPcodeFlow extends GhidraScript {
    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private Function resolveFunction(String token) throws Exception {
        Address address = null;
        try {
            address = toAddr(token);
        } catch (Exception ignored) {
            // Fall through to a name lookup.
        }
        if (address != null) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                function = currentProgram.getFunctionManager().getFunctionContaining(address);
            }
            if (function != null) return function;
        }

        Function exact = null;
        Function partial = null;
        int partialCount = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function function = it.next();
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

    private Address callTargetAddress(PcodeOpAST op) {
        if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 1) return null;
        Varnode target = op.getInput(0);
        if (target == null) return null;
        if (!target.isConstant()) return target.getAddress();
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset());
        } catch (Exception ignored) {
            return null;
        }
    }

    private Function resolveCallTarget(PcodeOpAST op) {
        Address target = callTargetAddress(op);
        if (target == null) return null;
        Function function = currentProgram.getFunctionManager().getFunctionAt(target);
        if (function != null) return function;
        // ARM/Thumb function pointers may carry bit 0 even when a recovered call
        // target has not been normalized by the current analysis database.
        long offset = target.getOffset();
        if ((offset & 1L) == 0L) return null;
        try {
            Address normalized = target.getAddressSpace().getAddress(offset & ~1L);
            return currentProgram.getFunctionManager().getFunctionAt(normalized);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String dataInputs(PcodeOpAST op) {
        int start = (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) ? 1 : 0;
        StringBuilder inputs = new StringBuilder();
        for (int index = start; index < op.getNumInputs(); index++) {
            if (inputs.length() > 0) inputs.append(';');
            inputs.append(varnodeToken(op.getInput(index)));
        }
        return inputs.length() == 0 ? "-" : inputs.toString();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: ExportFunctionPcodeFlow.java <function-address-or-name> <output.tsv>");
        }

        Function function = resolveFunction(args[0]);
        File output = new File(args[1]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open current program in decompiler");
        }

        long rows = 0;
        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results == null || !results.decompileCompleted()) {
                String message = results == null ? "no result" : results.getErrorMessage();
                throw new IllegalStateException("Decompile failed for " + function.getName(true) + ": " + message);
            }
            HighFunction high = results.getHighFunction();
            if (high == null) {
                throw new IllegalStateException("No HighFunction for " + function.getName(true));
            }

            try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(output), StandardCharsets.UTF_8))) {
                out.write("function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name");
                out.newLine();

                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                while (operations.hasNext() && !monitor.isCancelled()) {
                    PcodeOpAST op = operations.next();
                    SequenceNumber sequence = op.getSeqnum();
                    Function callee = resolveCallTarget(op);
                    String calleeEntry = callee == null ? "-" : cell(callee.getEntryPoint());
                    String calleeName = callee == null ? "-" : cell(callee.getName(true));
                    out.write(cell(function.getEntryPoint()) + "\t" +
                        cell(sequence.getTarget()) + "\t" + sequence.getTime() + "\t" +
                        cell(op.getMnemonic()) + "\t" + varnodeToken(op.getOutput()) + "\t" +
                        dataInputs(op) + "\t" + calleeEntry + "\t" + calleeName);
                    out.newLine();
                    rows++;
                }
            }
        } finally {
            decompiler.dispose();
        }

        println("Exported " + rows + " P-code flow rows for " + function.getName(true) +
            " at " + function.getEntryPoint() + " -> " + output);
        println("GHIDRA_FUNCTION_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraFunctionPcodeFlow/1");
        println("GHIDRA_FUNCTION_PCODE_FLOW_FUNCTION=" + function.getEntryPoint());
        println("GHIDRA_FUNCTION_PCODE_FLOW_ROWS=" + rows);
    }
}
