import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Resolve only constant tokens present in a metadata-only P-code TSV to
// defined String data. No program bytes or unrelated strings are exported.
public class ExportGhidraPcodeDefinedStrings extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraPcodeDefinedString/1";
    private static final Pattern CONSTANT = Pattern.compile("const:0x([0-9a-fA-F]+):[0-9]+");

    private String cell(Object value) {
        if (value == null) return "-";
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private Set<Long> readConstantAddresses(File input) throws Exception {
        LinkedHashSet<Long> result = new LinkedHashSet<Long>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(input), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                Matcher matcher = CONSTANT.matcher(line);
                while (matcher.find()) {
                    try {
                        result.add(Long.parseUnsignedLong(matcher.group(1), 16));
                    } catch (NumberFormatException ignored) {
                        // Ignore malformed or out-of-range tokens; no guessing.
                    }
                }
            }
        }
        return result;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraPcodeDefinedStrings.java <pcode.tsv> <output.tsv>");
        }
        File input = new File(args[0]);
        File output = new File(args[1]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        Set<Long> constants = readConstantAddresses(input);
        int resolved = 0;
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write("format\tconstant_address\tdata_address\tbyte_offset\tutf8_base64\tlength");
            out.newLine();
            for (Long value : constants) {
                if (monitor.isCancelled()) break;
                Address address;
                try {
                    address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(value.longValue());
                } catch (Exception ignored) {
                    continue;
                }
                Data data = currentProgram.getListing().getDefinedDataContaining(address);
                if (data == null || !(data.getValue() instanceof String)) continue;
                String text = (String)data.getValue();
                long offset;
                try {
                    offset = address.subtract(data.getAddress());
                } catch (Exception ignored) {
                    continue;
                }
                String encoded = Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
                out.write(String.join("\t",
                    FORMAT,
                    "0x" + Long.toUnsignedString(value.longValue(), 16),
                    cell(data.getAddress()),
                    "0x" + Long.toHexString(offset),
                    encoded,
                    Integer.toString(text.length())));
                out.newLine();
                resolved++;
            }
        }
        println("Resolved " + resolved + " defined strings from " + constants.size() +
            " P-code constants -> " + output);
    }
}
