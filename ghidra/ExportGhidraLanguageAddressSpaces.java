import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;

/** Export address-space IDs and properties required to interpret raw P-code. */
public class ExportGhidraLanguageAddressSpaces extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraLanguageAddressSpaces/1";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraLanguageAddressSpaces.java <output.json>");
        }

        File output = new File(args[0]).getAbsoluteFile();
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create output directory: " + parent);
        }

        AddressSpace[] spaces = currentProgram.getAddressFactory().getAllAddressSpaces();
        AddressSpace defaultDataSpace = currentProgram.getLanguage().getDefaultDataSpace();
        Arrays.sort(spaces, Comparator.comparingLong(
            space -> Integer.toUnsignedLong(space.getSpaceID())));
        StringBuilder row = new StringBuilder(256 + spaces.length * 192)
            .append("{\"format\":").append(q(FORMAT))
            .append(",\"language_id\":").append(q(currentProgram.getLanguageID().toString()))
            .append(",\"big_endian\":").append(currentProgram.getLanguage().isBigEndian())
            .append(",\"default_space\":").append(q(currentProgram.getLanguage().getDefaultSpace().getName()))
            .append(",\"default_data_space\":").append(q(
                defaultDataSpace == null ? null : defaultDataSpace.getName()))
            .append(",\"address_spaces\":[");
        for (int i = 0; i < spaces.length; i++) {
            monitor.checkCancelled();
            AddressSpace space = spaces[i];
            if (i > 0) row.append(',');
            row.append("{\"space_id\":").append(q("0x" + Long.toHexString(
                    Integer.toUnsignedLong(space.getSpaceID()))))
                .append(",\"name\":").append(q(space.getName()))
                .append(",\"pointer_size\":").append(space.getPointerSize())
                .append(",\"addressable_unit_size\":").append(space.getAddressableUnitSize())
                .append(",\"memory\":").append(space.isMemorySpace())
                .append(",\"loaded_memory\":").append(space.isLoadedMemorySpace())
                .append(",\"constant\":").append(space.isConstantSpace())
                .append(",\"register\":").append(space.isRegisterSpace())
                .append(",\"stack\":").append(space.isStackSpace())
                .append(",\"unique\":").append(space.isUniqueSpace())
                .append(",\"external\":").append(space.isExternalSpace())
                .append(",\"overlay\":").append(space.isOverlaySpace())
                .append('}');
        }
        row.append("]}\n");

        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            writer.write(row.toString());
        }
        println("Exported " + spaces.length + " language address spaces -> " + output);
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
