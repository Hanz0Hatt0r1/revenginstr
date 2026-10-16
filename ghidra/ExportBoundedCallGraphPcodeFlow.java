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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

// Evidence-only bounded direct-call graph export. Starting from one analyzed
// function, decompile a capped number of internal direct callees and emit the
// same metadata-only High P-code schema as ExportFunctionPcodeFlow.java.
// No strings, decompiler C, instruction bytes, or source assets are exported.
public class ExportBoundedCallGraphPcodeFlow extends GhidraScript {
    private static final int DEFAULT_MAX_DEPTH = 4;
    private static final int DEFAULT_MAX_FUNCTIONS = 96;
    private final List<PriorityRule> priorityRules = new ArrayList<PriorityRule>();
    private int defaultPriority = 0;

    private static class PriorityRule {
        final int priority;
        final String nameFragment;

        PriorityRule(int priority, String nameFragment) {
            this.priority = priority;
            this.nameFragment = nameFragment;
        }
    }

    private static class Work {
        final Function function;
        final int depth;

        Work(Function function, int depth) {
            this.function = function;
            this.depth = depth;
        }
    }

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

    private int priority(Function function) {
        String name = function.getName(true);
        int result = Integer.MAX_VALUE;
        for (PriorityRule rule : priorityRules) {
            if (name.contains(rule.nameFragment)) result = Math.min(result, rule.priority);
        }
        return result == Integer.MAX_VALUE ? defaultPriority : result;
    }

    private void configurePriorities(String[] args, int start) {
        for (int index = start; index < args.length; index++) {
            String option = args[index];
            if (option.startsWith("--default-priority=")) {
                defaultPriority = parseBound(
                    option.substring("--default-priority=".length()), "default-priority", defaultPriority);
                continue;
            }
            if (!option.startsWith("--priority=")) {
                throw new IllegalArgumentException("Unknown call-graph option: " + option);
            }
            String value = option.substring("--priority=".length());
            int separator = value.indexOf(':');
            if (separator <= 0 || separator == value.length() - 1) {
                throw new IllegalArgumentException(
                    "priority must be <rank>:<name-fragment>: " + value);
            }
            int rank = parseBound(value.substring(0, separator), "priority", 0);
            priorityRules.add(new PriorityRule(rank, value.substring(separator + 1)));
        }
    }

    private int parseBound(String text, String label, int fallback) {
        if (text == null || text.isEmpty()) return fallback;
        int value;
        try {
            value = Integer.parseInt(text, 10);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(label + " must be a decimal integer: " + text);
        }
        if (value < 0) throw new IllegalArgumentException(label + " must be >= 0");
        return value;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportBoundedCallGraphPcodeFlow.java " +
                "<root-function-address-or-name> <output.tsv> [max-depth] [max-functions] " +
                "[--default-priority=N] [--priority=N:name-fragment]...");
        }

        Function root = resolveFunction(args[0]);
        File output = new File(args[1]);
        int maxDepth = parseBound(args.length >= 3 ? args[2] : null, "max-depth", DEFAULT_MAX_DEPTH);
        int maxFunctions = parseBound(args.length >= 4 ? args[3] : null, "max-functions", DEFAULT_MAX_FUNCTIONS);
        if (maxFunctions < 1) throw new IllegalArgumentException("max-functions must be >= 1");
        configurePriorities(args, Math.min(args.length, 4));

        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open current program in decompiler");
        }

        ArrayDeque<Work> queue = new ArrayDeque<Work>();
        Set<Address> scheduled = new HashSet<Address>();
        queue.add(new Work(root, 0));
        scheduled.add(root.getEntryPoint());

        long rows = 0;
        int functions = 0;
        boolean capped = false;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write("function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name");
            out.newLine();

            while (!queue.isEmpty() && !monitor.isCancelled()) {
                if (functions >= maxFunctions) {
                    capped = true;
                    break;
                }
                Work work = queue.removeFirst();
                Function function = work.function;
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted()) {
                    String message = results == null ? "no result" : results.getErrorMessage();
                    throw new IllegalStateException(
                        "Decompile failed for " + function.getName(true) + " at " +
                        function.getEntryPoint() + ": " + message);
                }
                HighFunction high = results.getHighFunction();
                if (high == null) {
                    throw new IllegalStateException("No HighFunction for " + function.getName(true));
                }

                List<Function> callees = new ArrayList<Function>();
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

                    if (work.depth < maxDepth && callee != null && !callee.isExternal() &&
                            !scheduled.contains(callee.getEntryPoint())) {
                        callees.add(callee);
                        scheduled.add(callee.getEntryPoint());
                    }
                }
                functions++;

                callees.sort(Comparator
                    .comparingInt((Function value) -> priority(value))
                    .thenComparing(value -> value.getEntryPoint()));
                for (Function callee : callees) {
                    queue.addLast(new Work(callee, work.depth + 1));
                }
            }
        } finally {
            decompiler.dispose();
        }

        println("Exported " + rows + " P-code flow rows across " + functions +
            " functions from " + root.getName(true) + " at " + root.getEntryPoint() +
            " (max-depth=" + maxDepth + ", max-functions=" + maxFunctions +
            ", capped=" + capped + ") -> " + output);
    }
}
