import ghidra.app.script.GhidraScript;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/** Export the language-scoped index/name table used by CALLOTHER P-code. */
public class ExportGhidraLanguageUserops extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraLanguageUserops/1";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraLanguageUserops.java <output.json>");
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        int count = currentProgram.getLanguage().getNumberOfUserDefinedOpNames();
        StringBuilder row = new StringBuilder(128 + count * 48)
            .append("{\"format\":").append(q(FORMAT))
            .append(",\"language_id\":").append(q(currentProgram.getLanguageID().toString()))
            .append(",\"userop_count\":").append(count)
            .append(",\"userops\":[");
        for (int i = 0; i < count; i++) {
            monitor.checkCancelled();
            if (i > 0) row.append(',');
            row.append("{\"index\":").append(i)
                .append(",\"name\":").append(q(currentProgram.getLanguage().getUserDefinedOpName(i)))
                .append('}');
        }
        row.append("]}\n");

        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            writer.write(row.toString());
        }
        println("Exported " + count + " language userops -> " + output);
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
}
