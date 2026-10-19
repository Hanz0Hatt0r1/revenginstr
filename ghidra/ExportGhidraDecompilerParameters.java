import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.FunctionPrototype;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Export read-only formal-parameter observations from Ghidra High P-code. */
public class ExportGhidraDecompilerParameters extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraDecompilerParameters/1";

    private static class PlanRow {
        String planId;
        String requestedEntry;
        String resolution;
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

    private static String cell(Object value) {
        return value == null ? null : String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private static String typeKind(DataType type) {
        if (type == null) return "unknown";
        if (type instanceof VoidDataType) return "void";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array || type instanceof Composite) return "aggregate";
        return type.getLength() > 0 ? "scalar" : "unknown";
    }

    private static String typeJson(DataType type, int observedWidth) {
        if (type == null) {
            return "{\"kind\":\"unknown\",\"name\":\"undefined\",\"path\":\"/\",\"width_bytes\":" +
                (observedWidth > 0 ? observedWidth : "null") + "}";
        }
        int length = type.getLength();
        int width = observedWidth > 0 ? observedWidth : length;
        return "{\"kind\":" + q(typeKind(type)) + ",\"name\":" + q(type.getName()) +
            ",\"path\":" + q(type.getPathName()) + ",\"width_bytes\":" +
            (width > 0 ? Integer.toString(width) : "null") + "}";
    }

    private List<PlanRow> readPlan(File file) throws Exception {
        ArrayList<PlanRow> rows = new ArrayList<PlanRow>();
        Set<String> ids = new HashSet<String>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            boolean first = true;
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                if (first) {
                    if (!"plan_id\trequested_entry\tresolution".equals(line))
                        throw new IllegalArgumentException("Expected plan_id, requested_entry, resolution header");
                    first = false;
                    continue;
                }
                String[] cells = line.split("\\t", -1);
                if (cells.length != 3 || cells[0].isEmpty() || cells[1].isEmpty() ||
                    !("exact".equals(cells[2]) || "containing".equals(cells[2])))
                    throw new IllegalArgumentException("Invalid function parameter plan row: " + line);
                if (!ids.add(cells[0])) throw new IllegalArgumentException("Duplicate plan_id: " + cells[0]);
                PlanRow row = new PlanRow();
                row.planId = cells[0]; row.requestedEntry = cells[1]; row.resolution = cells[2];
                rows.add(row);
            }
        }
        if (rows.isEmpty()) throw new IllegalArgumentException("Function parameter plan is empty");
        return rows;
    }

    private Function resolve(PlanRow row) throws Exception {
        Address address = toAddr(row.requestedEntry);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionAt(address);
        if (function == null && "containing".equals(row.resolution))
            function = functions.getFunctionContaining(address);
        if (function == null) throw new IllegalArgumentException("Function not found: " + row.requestedEntry);
        return function;
    }

    private String parametersJson(LocalSymbolMap symbols) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < symbols.getNumParams(); index++) {
            if (index > 0) out.append(',');
            HighSymbol symbol = symbols.getParamSymbol(index);
            if (symbol == null) throw new IllegalStateException("Missing HighSymbol at parameter index " + index);
            DataType type = symbol.getDataType();
            out.append("{\"index\":").append(index)
                .append(",\"name\":").append(q(cell(symbol.getName())))
                .append(",\"type\":").append(typeJson(type, symbol.getSize()))
                .append(",\"storage\":").append(q(cell(symbol.getStorage())))
                .append(",\"is_this_pointer\":").append(symbol.isThisPointer())
                .append(",\"is_hidden_return\":").append(symbol.isHiddenReturn())
                .append(",\"is_type_locked\":").append(symbol.isTypeLocked())
                .append('}');
        }
        return out.append(']').toString();
    }

    private String recordJson(PlanRow row, Function function, DecompileResults result) {
        String status;
        HighFunction high = result == null ? null : result.getHighFunction();
        if (function.isExternal()) status = "external";
        else if (result == null || !result.decompileCompleted()) status = "decompile_failed";
        else if (high == null || high.getLocalSymbolMap() == null) status = "no_high_function";
        else if (high.getFunctionPrototype() == null) status = "prototype_unavailable";
        else status = "complete";
        LocalSymbolMap symbols = "complete".equals(status) ? high.getLocalSymbolMap() : null;
        FunctionPrototype prototype = "complete".equals(status) ? high.getFunctionPrototype() : null;
        String error = status.equals("decompile_failed") && result != null ? result.getErrorMessage() : null;
        String returnType = prototype == null ? "null" : typeJson(prototype.getReturnType(),
            prototype.getReturnType() == null ? 0 : prototype.getReturnType().getLength());
        String source = function.getSignatureSource() == null ? "UNKNOWN" : function.getSignatureSource().toString();
        return "{\"format\":" + q(FORMAT) + ",\"plan_id\":" + q(row.planId) +
            ",\"program_id\":" + q(currentProgram.getName()) +
            ",\"program_sha256\":" + q(currentProgram.getExecutableSHA256()) +
            ",\"architecture\":{\"language_id\":" + q(currentProgram.getLanguageID().toString()) +
            ",\"pointer_width_bytes\":" + currentProgram.getDefaultPointerSize() +
            ",\"endianness\":" + q(currentProgram.getLanguage().isBigEndian() ? "big" : "little") + "}" +
            ",\"requested_entry\":" + q(row.requestedEntry) +
            ",\"function_entry\":" + q(function.getEntryPoint().toString(false, false)) +
            ",\"name\":" + q(function.getName(true)) +
            ",\"is_external\":" + function.isExternal() +
            ",\"status\":" + q(status) +
            ",\"signature_source\":" + q(source) +
            ",\"calling_convention\":" + q(cell(function.getCallingConventionName())) +
            ",\"has_varargs\":" + (prototype != null && prototype.isVarArg()) +
            ",\"parameter_count\":" + (symbols == null ? "null" : Integer.toString(symbols.getNumParams())) +
            ",\"parameters\":" + (symbols == null ? "[]" : parametersJson(symbols)) +
            ",\"return_type\":" + returnType +
            ",\"return_storage\":" + q(prototype == null ? null : cell(prototype.getReturnStorage())) +
            ",\"error\":" + q(error) + "}";
    }

    private boolean isComplete(Function function, DecompileResults result) {
        return !function.isExternal() && result != null && result.decompileCompleted() &&
            result.getHighFunction() != null && result.getHighFunction().getLocalSymbolMap() != null &&
            result.getHighFunction().getFunctionPrototype() != null;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2)
            throw new IllegalArgumentException("Usage: ExportGhidraDecompilerParameters.java <plan.tsv> <output.jsonl>");
        String sha = currentProgram.getExecutableSHA256();
        if (sha == null || !sha.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("Ghidra program has no valid executable SHA-256");
        List<PlanRow> plan = readPlan(new File(args[0]));
        File output = new File(args[1]);
        if (output.getCanonicalFile().equals(new File(args[0]).getCanonicalFile()))
            throw new IllegalArgumentException("plan and output paths must differ");
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs())
            throw new IllegalStateException("cannot create output directory: " + parent);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.toggleCCode(false) || !decompiler.toggleSyntaxTree(true) || !decompiler.openProgram(currentProgram))
            throw new IllegalStateException("Could not configure/open read-only decompiler");
        int complete = 0;
        int failures = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (PlanRow row : plan) {
                monitor.checkCancelled();
                Function function = resolve(row);
                DecompileResults result = function.isExternal() ? null : decompiler.decompileFunction(function, 60, monitor);
                String json = recordJson(row, function, result);
                out.write(json); out.newLine();
                if (isComplete(function, result)) complete++;
                else failures++;
            }
        } finally {
            decompiler.dispose();
        }
        if (complete + failures != plan.size()) throw new IllegalStateException("incomplete parameter export");
        println("GHIDRA_DECOMPILER_PARAMETERS_FORMAT=" + FORMAT);
        println("Ghidra decompiler parameter export complete: " + plan.size() + " rows; complete=" + complete + "; unavailable=" + failures + " -> " + output);
    }
}
