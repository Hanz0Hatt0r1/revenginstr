import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

// Export generic program metadata, never program bytes, decompiler text, or assets.
public class ExportGhidraProgramIndex extends GhidraScript {
    private BufferedWriter open(String prefix, String suffix, String header) throws Exception {
        File file = new File(prefix + "." + suffix + ".tsv.gz");
        File parent = file.getParentFile();
        if (parent != null) parent.mkdirs();
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(new FileOutputStream(file)), StandardCharsets.UTF_8));
        writer.write(header);
        writer.newLine();
        return writer;
    }

    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String address(Object address) {
        return address == null ? "-" : cell(address);
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraProgramIndex.java <output-path-prefix>");
        }
        String prefix = args[0];
        long functions = 0;
        long symbols = 0;
        long strings = 0;
        long xrefs = 0;
        long calls = 0;

        try (BufferedWriter out = open(prefix, "functions", "entry\tname\taddress_count\tis_external\tsignature")) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function function = it.next();
                out.write(address(function.getEntryPoint()) + "\t" + cell(function.getName(true)) +
                    "\t" + function.getBody().getNumAddresses() + "\t" + function.isExternal() +
                    "\t" + cell(function.getSignature()));
                out.newLine();
                functions++;
            }
        }

        try (BufferedWriter out = open(prefix, "symbols", "address\tname\ttype\tsource\tis_primary")) {
            SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = it.next();
                out.write(address(symbol.getAddress()) + "\t" + cell(symbol.getName(true)) +
                    "\t" + cell(symbol.getSymbolType()) + "\t" + cell(symbol.getSource()) +
                    "\t" + symbol.isPrimary());
                out.newLine();
                symbols++;
            }
        }

        try (BufferedWriter out = open(prefix, "strings", "address\tutf8_base64\tlength")) {
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Data data = it.next();
                if (!(data.getValue() instanceof String)) continue;
                String value = (String)data.getValue();
                String encoded = Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
                out.write(address(data.getAddress()) + "\t" + encoded + "\t" + value.length());
                out.newLine();
                strings++;
            }
        }

        try (BufferedWriter out = open(prefix, "xrefs", "from\tto\ttype\toperand\tsource");
             BufferedWriter callOut = open(prefix, "calls", "caller_entry\tcall_site\tcallee_entry")) {
            ReferenceIterator it = currentProgram.getReferenceManager()
                .getReferenceIterator(currentProgram.getMinAddress());
            while (it.hasNext() && !monitor.isCancelled()) {
                Reference ref = it.next();
                out.write(address(ref.getFromAddress()) + "\t" + address(ref.getToAddress()) +
                    "\t" + cell(ref.getReferenceType()) + "\t" + ref.getOperandIndex() +
                    "\t" + cell(ref.getSource()));
                out.newLine();
                xrefs++;
                if (!ref.getReferenceType().isCall()) continue;
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                Function callee = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (caller == null || callee == null) continue;
                callOut.write(address(caller.getEntryPoint()) + "\t" +
                    address(ref.getFromAddress()) + "\t" + address(callee.getEntryPoint()));
                callOut.newLine();
                calls++;
            }
        }

        println("Indexed " + currentProgram.getName() + ": " + functions + " functions, " +
            symbols + " symbols, " + strings + " strings, " + xrefs + " xrefs, " +
            calls + " resolved calls");
    }
}
