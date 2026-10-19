import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

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

/** Export structured function signatures from a pinned, already analyzed Ghidra program. */
public class ExportGhidraFunctionPrototypes extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionPrototype/1";

    private static class PlanRow {
        String planId;
        String requestedEntry;
        String resolution;
    }

    private List<PlanRow> readPlan(File file) throws Exception {
        ArrayList<PlanRow> rows = new ArrayList<PlanRow>();
        Set<String> planIds = new HashSet<String>();
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
                if (cells.length != 3) throw new IllegalArgumentException("Expected three plan columns: " + line);
                PlanRow row = new PlanRow();
                row.planId = cells[0];
                row.requestedEntry = cells[1];
                row.resolution = cells[2];
                if (row.planId.isEmpty() || row.requestedEntry.isEmpty() ||
                    !("exact".equals(row.resolution) || "containing".equals(row.resolution)))
                    throw new IllegalArgumentException("Invalid function identity plan row: " + line);
                if (!planIds.add(row.planId)) throw new IllegalArgumentException("Duplicate plan_id: " + row.planId);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) throw new IllegalArgumentException("Function prototype plan is empty");
        return rows;
    }

    private Function resolve(PlanRow row) throws Exception {
        Address address = toAddr(row.requestedEntry);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionAt(address);
        if (function == null && "containing".equals(row.resolution))
            function = functions.getFunctionContaining(address);
        if (function == null) throw new IllegalArgumentException("Function not found for entry: " + row.requestedEntry);
        return function;
    }

    private static String typeKind(DataType type) {
        if (type == null) return "unknown";
        if (type instanceof VoidDataType) return "void";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array || type instanceof Composite) return "aggregate";
        return type.getLength() > 0 ? "scalar" : "unknown";
    }

    private static String typeJson(DataType type) {
        if (type == null) return "{\"kind\":\"unknown\",\"name\":\"undefined\",\"path\":\"/\",\"width_bytes\":null,\"target_name\":null,\"target_path\":null}";
        String targetName = null;
        String targetPath = null;
        if (type instanceof Pointer) {
            DataType target = ((Pointer) type).getDataType();
            if (target != null) {
                targetName = target.getName();
                targetPath = target.getPathName();
            }
        }
        int length = type.getLength();
        return "{\"kind\":" + q(typeKind(type)) +
            ",\"name\":" + q(type.getName()) +
            ",\"path\":" + q(type.getPathName()) +
            ",\"width_bytes\":" + (length > 0 ? Integer.toString(length) : "null") +
            ",\"target_name\":" + q(targetName) +
            ",\"target_path\":" + q(targetPath) + "}";
    }

    private String recordJson(PlanRow row, Function function) {
        Parameter[] parameters = function.getParameters();
        StringBuilder params = new StringBuilder("[");
        for (int i = 0; i < parameters.length; i++) {
            if (i > 0) params.append(',');
            Parameter parameter = parameters[i];
            SourceType source = parameter.getSource();
            params.append("{\"index\":").append(i)
                .append(",\"name\":").append(q(parameter.getName()))
                .append(",\"source\":").append(q(source == null ? "UNKNOWN" : source.toString()))
                .append(",\"type\":").append(typeJson(parameter.getDataType())).append('}');
        }
        params.append(']');

        return "{\"format\":" + q(FORMAT) +
            ",\"plan_id\":" + q(row.planId) +
            ",\"program_id\":" + q(currentProgram.getName()) +
            ",\"program_sha256\":" + q(currentProgram.getExecutableSHA256()) +
            ",\"architecture\":{" +
                "\"language_id\":" + q(currentProgram.getLanguageID().toString()) +
                ",\"pointer_width_bytes\":" + currentProgram.getDefaultPointerSize() +
                ",\"endianness\":" + q(currentProgram.getLanguage().isBigEndian() ? "big" : "little") + "}" +
            ",\"requested_entry\":" + q(row.requestedEntry) +
            ",\"resolved_entry\":" + q(function.getEntryPoint().toString(false, false)) +
            ",\"name\":" + q(function.getName()) +
            ",\"qualified_name\":" + q(function.getName(true)) +
            ",\"is_external\":" + function.isExternal() +
            ",\"signature_source\":" + q(function.getSignatureSource().toString()) +
            ",\"calling_convention\":" + q(function.getCallingConventionName()) +
            ",\"has_varargs\":" + function.getSignature().hasVarArgs() +
            ",\"parameter_count\":" + parameters.length +
            ",\"parameters\":" + params +
            ",\"return_type\":" + typeJson(function.getReturnType()) +
            ",\"signature\":" + q(function.getSignature().getPrototypeString()) + "}";
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

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2)
            throw new IllegalArgumentException("Usage: ExportGhidraFunctionPrototypes.java <plan.tsv> <output.jsonl>");
        String executableSha256 = currentProgram.getExecutableSHA256();
        if (executableSha256 == null || !executableSha256.matches("[0-9a-f]{64}"))
            throw new IllegalStateException("Ghidra program has no valid executable SHA-256");
        List<PlanRow> plan = readPlan(new File(args[0]));
        File output = new File(args[1]);
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs())
            throw new IllegalStateException("cannot create output directory: " + parent);
        int exported = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            for (PlanRow row : plan) {
                monitor.checkCancelled();
                out.write(recordJson(row, resolve(row)));
                out.newLine();
                exported++;
            }
        }
        if (exported != plan.size()) throw new IllegalStateException("incomplete prototype export");
        println("Ghidra function prototype export complete: " + exported + " rows -> " + output);
    }
}
