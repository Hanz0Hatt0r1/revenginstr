import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

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

// Metadata-only export of requested Ghidra function identities.
public class ExportGhidraFunctionIdentities extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraFunctionIdentity/1";

    private static class PlanRow {
        String planId;
        String requestedEntry;
        String resolution;
    }

    private String cell(Object value) {
        if (value == null) return "-";
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
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

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2)
            throw new IllegalArgumentException("Usage: ExportGhidraFunctionIdentities.java <plan.tsv> <output.tsv>");
        List<PlanRow> plan = readPlan(new File(args[0]));
        File output = new File(args[1]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write("format\tplan_id\trequested_entry\tresolved_entry\tshort_name\tqualified_name\tsignature\tis_external");
            out.newLine();
            for (PlanRow row : plan) {
                if (monitor.isCancelled()) break;
                Function function = resolve(row);
                out.write(String.join("\t",
                    FORMAT,
                    cell(row.planId),
                    cell(row.requestedEntry),
                    cell(function.getEntryPoint()),
                    cell(function.getName()),
                    cell(function.getName(true)),
                    cell(function.getSignature()),
                    Boolean.toString(function.isExternal())));
                out.newLine();
            }
        }
        println("Exported " + plan.size() + " function identities");
    }
}
