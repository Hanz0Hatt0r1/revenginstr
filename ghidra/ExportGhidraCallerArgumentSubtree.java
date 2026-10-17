import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Metadata-only bounded SSA exporter for actual arguments at direct caller sites.
// Edge labels distinguish value flow from LOAD-address/base/offset flow.
public class ExportGhidraCallerArgumentSubtree extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraCallerArgumentSubtree/1";
    private static final String PARAMETER_ROOT_FORMAT = "REVENGINSTR.GhidraCallerArgumentParameterRoot/1";
    private static final int MAX_DEPTH = 12;
    private static final int MAX_NODES = 96;
    private static final int MAX_CALLERS = 128;

    private static class PlanRow {
        String planId;
        String calleeEntry;
        int parameterIndex;
    }

    private static class TypeInfo {
        int depth;
        DataType pointee;
        TypeInfo(int d, DataType p) { depth = d; pointee = p; }
    }

    private String cell(Object v) {
        if (v == null) return "-";
        return String.valueOf(v).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private DataType unwrap(DataType t) {
        DataType c = t;
        int guard = 0;
        while (c instanceof TypeDef && guard++ < 8) {
            DataType n = ((TypeDef)c).getBaseDataType();
            if (n == null || n == c) break;
            c = n;
        }
        return c;
    }

    private TypeInfo inspect(DataType t) {
        DataType c = unwrap(t);
        int depth = 0;
        DataType pointee = null;
        while (c instanceof Pointer) {
            depth++;
            DataType n = unwrap(((Pointer)c).getDataType());
            if (depth == 1) pointee = n;
            if (n == null || n == c) break;
            c = n;
        }
        return new TypeInfo(depth, pointee);
    }

    private DataType highType(Varnode n) {
        HighVariable h = n == null ? null : n.getHigh();
        return h == null ? null : h.getDataType();
    }

    private String token(Varnode n) {
        if (n == null) return "-";
        if (n.isConstant()) return "const:0x" + Long.toUnsignedString(n.getOffset(), 16) + ":" + n.getSize();
        PcodeOp def = n.getDef();
        if (def != null) {
            SequenceNumber s = def.getSeqnum();
            return "def:" + def.getMnemonic() + "@" + cell(s.getTarget()) + ":" + s.getTime() + ":" + n.getSize();
        }
        String kind = n.isRegister() ? "register" : n.isUnique() ? "unique" : n.isAddress() ? "address" : "input";
        return kind + ":" + cell(n.getAddress()) + ":" + n.getSize();
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

    private Address callTargetAddress(PcodeOp op) {
        if (op == null || op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 1) return null;
        Varnode target = op.getInput(0);
        if (target == null) return null;
        if (!target.isConstant()) return target.getAddress();
        try { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset()); }
        catch (Exception ignored) { return null; }
    }

    private Function resolveCallTarget(PcodeOp op) {
        Address a = callTargetAddress(op);
        if (a == null) return null;
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionAt(a);
        if (f != null) return f;
        long off = a.getOffset();
        if ((off & 1L) == 0L) return null;
        try { return fm.getFunctionAt(a.getAddressSpace().getAddress(off & ~1L)); }
        catch (Exception ignored) { return null; }
    }

    private Set<Function> directCallers(Function callee) {
        LinkedHashSet<Function> out = new LinkedHashSet<Function>();
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(callee.getEntryPoint());
        FunctionManager fm = currentProgram.getFunctionManager();
        while (refs.hasNext() && out.size() < MAX_CALLERS) {
            Reference ref = refs.next();
            if (ref == null || ref.getFromAddress() == null) continue;
            Function f = fm.getFunctionContaining(ref.getFromAddress());
            if (f != null && !f.equals(callee)) out.add(f);
        }
        return out;
    }

    private Function resolveFunction(String token) throws Exception {
        Address a = toAddr(token);
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) throw new IllegalArgumentException("Function not found: " + token);
        return f;
    }

    private List<PlanRow> readPlan(File file) throws Exception {
        ArrayList<PlanRow> rows = new ArrayList<PlanRow>();
        HashSet<String> planIds = new HashSet<String>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line; boolean first = true;
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                if (first) {
                    if (!"plan_id\tcallee_entry\tparameter_index".equals(line))
                        throw new IllegalArgumentException("Expected plan_id, callee_entry, parameter_index header");
                    first = false;
                    continue;
                }
                String[] c = line.split("\\t", -1);
                if (c.length != 3) throw new IllegalArgumentException("Expected plan_id, callee_entry, parameter_index: " + line);
                PlanRow r = new PlanRow();
                r.planId = c[0]; r.calleeEntry = c[1]; r.parameterIndex = Integer.parseInt(c[2]);
                if (r.planId.isEmpty() || r.calleeEntry.isEmpty() || r.parameterIndex < 0)
                    throw new IllegalArgumentException("Invalid plan row: " + line);
                if (!planIds.add(r.planId)) throw new IllegalArgumentException("Duplicate plan_id: " + r.planId);
                rows.add(r);
            }
        }
        return rows;
    }

    private void writeHeader(BufferedWriter out) throws Exception {
        out.write("format\trow_type\tplan_id\tcallee_entry\tparameter_index\tdirect_caller_functions\t" +
            "caller_functions_decompiled\tcaller_functions_failed\tcallers_with_matched_calls\tmatched_caller_calls\t" +
            "caller_entry\tcaller_name\tcaller_call_site\tnode_id\tparent_node_id\tinput_index\tdepth\tedge_kind\t" +
            "node_token\ttype_display\tpointer_depth\tpointee_type_display\tconstant_value\tdefining_opcode\t" +
            "defining_address\tdefining_time\tcall_target_entry\tcall_target_name\ttruncation\tstatus");
        out.newLine();
    }

    private void writeParameterRootHeader(BufferedWriter out) throws Exception {
        out.write("format\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\tcaller_call_site\t" +
            "caller_parameter_index\targument_node_id\tstatus");
        out.newLine();
    }

    private void writeNode(BufferedWriter out, PlanRow p, Function caller, Address callSite, Varnode node,
            int nodeId, int parentId, int inputIndex, int depth, String edge, String truncation) throws Exception {
        DataType type = highType(node);
        TypeInfo ti = inspect(type);
        PcodeOp def = node == null ? null : node.getDef();
        String op = def == null ? "-" : def.getMnemonic();
        String defAddr = def == null ? "-" : cell(def.getSeqnum().getTarget());
        String defTime = def == null ? "-" : Integer.toString(def.getSeqnum().getTime());
        Function target = def == null ? null : resolveCallTarget(def);
        String constant = node != null && node.isConstant() ? "0x" + Long.toUnsignedString(node.getOffset(), 16) : "-";
        out.write(String.join("\t",
            FORMAT, "node", cell(p.planId), cell(p.calleeEntry), Integer.toString(p.parameterIndex),
            "-", "-", "-", "-", "-", cell(caller.getEntryPoint()),
            cell(caller.getName()), cell(callSite), Integer.toString(nodeId), Integer.toString(parentId),
            Integer.toString(inputIndex), Integer.toString(depth), cell(edge), token(node),
            cell(type == null ? null : type.getDisplayName()), Integer.toString(ti.depth),
            cell(ti.pointee == null ? null : ti.pointee.getDisplayName()), constant, op, defAddr, defTime,
            cell(target == null ? null : target.getEntryPoint()), cell(target == null ? null : target.getName()),
            cell(truncation), "-"));
        out.newLine();
    }

    private int walk(BufferedWriter out, PlanRow p, Function caller, Address callSite, Varnode node,
            int parentId, int inputIndex, int depth, String edge, int[] nextId, int[] budget, Set<Varnode> path) throws Exception {
        if (node == null || budget[0] >= MAX_NODES) return -1;
        int id = nextId[0]++;
        budget[0]++;
        String trunc = "-";
        if (depth >= MAX_DEPTH) trunc = "depth";
        else if (path.contains(node)) trunc = "cycle";
        writeNode(out, p, caller, callSite, node, id, parentId, inputIndex, depth, edge, trunc);
        if (!"-".equals(trunc)) return id;
        PcodeOp def = node.getDef();
        if (def == null || def.getOpcode() == PcodeOp.CALL || def.getOpcode() == PcodeOp.CALLIND) return id;

        HashSet<Varnode> nextPath = new HashSet<Varnode>(path); nextPath.add(node);
        int opcode = def.getOpcode();
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INDIRECT) && def.getNumInputs() >= 1) {
            walk(out, p, caller, callSite, def.getInput(0), id, 0, depth + 1, "value", nextId, budget, nextPath);
        } else if (opcode == PcodeOp.MULTIEQUAL) {
            for (int i = 0; i < def.getNumInputs() && budget[0] < MAX_NODES; i++)
                walk(out, p, caller, callSite, def.getInput(i), id, i, depth + 1, "value", nextId, budget, nextPath);
        } else if (opcode == PcodeOp.LOAD && def.getNumInputs() >= 2) {
            walk(out, p, caller, callSite, def.getInput(1), id, 1, depth + 1, "load_address", nextId, budget, nextPath);
        } else if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
            for (int i = 0; i < def.getNumInputs() && budget[0] < MAX_NODES; i++)
                walk(out, p, caller, callSite, def.getInput(i), id, i, depth + 1, i == 0 ? "base" : "offset", nextId, budget, nextPath);
        } else if (opcode == PcodeOp.PTRADD) {
            String[] edges = {"base", "offset_index", "offset_scale"};
            for (int i = 0; i < def.getNumInputs() && budget[0] < MAX_NODES; i++)
                walk(out, p, caller, callSite, def.getInput(i), id, i, depth + 1, i < edges.length ? edges[i] : "offset", nextId, budget, nextPath);
        } else {
            for (int i = 0; i < def.getNumInputs() && budget[0] < MAX_NODES; i++)
                walk(out, p, caller, callSite, def.getInput(i), id, i, depth + 1, "other_input", nextId, budget, nextPath);
        }
        return id;
    }

    private void writeSummary(BufferedWriter out, PlanRow p, int direct, int decompiled, int failed,
            int callersWithMatched, int matched, String status) throws Exception {
        out.write(String.join("\t",
            FORMAT, "summary", cell(p.planId), cell(p.calleeEntry), Integer.toString(p.parameterIndex),
            Integer.toString(direct), Integer.toString(decompiled),
            Integer.toString(failed), Integer.toString(callersWithMatched), Integer.toString(matched),
            "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", cell(status)));
        out.newLine();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && args.length != 4) throw new IllegalArgumentException(
            "Usage: ExportGhidraCallerArgumentSubtree.java <plan.tsv> <output.tsv> [--parameter-root-output <roots.tsv>]");
        if (args.length == 4 && !"--parameter-root-output".equals(args[2]))
            throw new IllegalArgumentException("Expected --parameter-root-output before the roots TSV path");
        List<PlanRow> plan = readPlan(new File(args[0]));
        File output = new File(args[1]); File parent = output.getParentFile(); if (parent != null) parent.mkdirs();
        File parameterRootOutput = args.length == 4 ? new File(args[3]) : null;
        if (parameterRootOutput != null && output.getCanonicalFile().equals(parameterRootOutput.getCanonicalFile()))
            throw new IllegalArgumentException("subtree and parameter-root outputs must be different files");
        if (parameterRootOutput != null && parameterRootOutput.getParentFile() != null)
            parameterRootOutput.getParentFile().mkdirs();
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Could not open current program");
        int parameterRootRows = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8));
             BufferedWriter parameterRootOut = parameterRootOutput == null ? null : new BufferedWriter(
                 new OutputStreamWriter(new FileOutputStream(parameterRootOutput), StandardCharsets.UTF_8))) {
            writeHeader(out);
            if (parameterRootOut != null) writeParameterRootHeader(parameterRootOut);
            for (PlanRow p : plan) {
                if (monitor.isCancelled()) break;
                Function callee = resolveFunction(p.calleeEntry);
                Set<Function> callers = directCallers(callee);
                int decompiled = 0, failed = 0, callersWithMatched = 0, matched = 0;
                for (Function caller : callers) {
                    DecompileResults results = decompiler.decompileFunction(caller, 60, monitor);
                    if (results == null || !results.decompileCompleted() || results.getHighFunction() == null) { failed++; continue; }
                    decompiled++;
                    HighFunction high = results.getHighFunction();
                    boolean callerMatched = false;
                    Iterator<PcodeOpAST> ops = high.getPcodeOps();
                    while (ops.hasNext() && !monitor.isCancelled()) {
                        PcodeOpAST op = ops.next();
                        if (op.getOpcode() != PcodeOp.CALL) continue;
                        Function target = resolveCallTarget(op);
                        if (target == null || !target.getEntryPoint().equals(callee.getEntryPoint())) continue;
                        int arg = p.parameterIndex + 1;
                        if (op.getNumInputs() <= arg) continue;
                        callerMatched = true; matched++;
                        int[] nextId = {0}; int[] budget = {0};
                        Varnode argumentRoot = op.getInput(arg);
                        int argumentNodeId = walk(out, p, caller, op.getSeqnum().getTarget(), argumentRoot,
                            -1, -1, 0, "root", nextId, budget, new HashSet<Varnode>());
                        int callerParameterIndex = parameterIndex(high, argumentRoot);
                        if (parameterRootOut != null && argumentNodeId >= 0 && callerParameterIndex >= 0) {
                            parameterRootOut.write(String.join("\t", PARAMETER_ROOT_FORMAT,
                                cell(p.planId), cell(p.calleeEntry), Integer.toString(p.parameterIndex),
                                cell(caller.getEntryPoint()), cell(op.getSeqnum().getTarget()),
                                Integer.toString(callerParameterIndex), Integer.toString(argumentNodeId),
                                "direct_parameter_root"));
                            parameterRootOut.newLine();
                            parameterRootRows++;
                        }
                    }
                    if (callerMatched) callersWithMatched++;
                }
                String status;
                if (callers.isEmpty()) status = "no_direct_callers";
                else if (failed != 0) status = "caller_decompile_incomplete";
                else if (callersWithMatched != callers.size()) status = "caller_function_without_matched_call";
                else status = "complete_caller_argument_subtrees";
                writeSummary(out, p, callers.size(), decompiled, failed, callersWithMatched, matched, status);
            }
        } finally { decompiler.dispose(); }
        println("CALLER_ARGUMENT_SUBTREE_FORMAT=" + FORMAT);
        println("CALLER_ARGUMENT_SUBTREE_PLANS=" + plan.size());
        println("CALLER_ARGUMENT_SUBTREE_OUTPUT=" + output.getAbsolutePath());
        if (parameterRootOutput != null) {
            println("CALLER_ARGUMENT_PARAMETER_ROOT_FORMAT=" + PARAMETER_ROOT_FORMAT);
            println("CALLER_ARGUMENT_PARAMETER_ROOT_ROWS=" + parameterRootRows);
            println("CALLER_ARGUMENT_PARAMETER_ROOT_OUTPUT=" + parameterRootOutput.getAbsolutePath());
        }
    }
}
