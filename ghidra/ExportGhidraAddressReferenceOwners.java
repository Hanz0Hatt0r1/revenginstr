import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

// Export direct xref ownership metadata for caller-supplied addresses only.
public class ExportGhidraAddressReferenceOwners extends GhidraScript {
    private static final String FORMAT = "REVENGINSTR.GhidraAddressReferenceOwner/1";
    private static final String HEADER = "format\ttarget_address\ttarget_block\ttarget_symbol\t" +
        "reference_from\treference_type\treference_source\toperand_index\tfrom_symbol\t" +
        "from_instruction\tcontaining_function_entry\tcontaining_function_name";

    private String clean(String value) {
        if (value == null || value.isEmpty()) return "-";
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    private String symbolAt(Address address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        return symbol == null ? "-" : clean(symbol.getName(true));
    }

    private void writeRow(BufferedWriter out, String... fields) throws Exception {
        out.write(FORMAT);
        for (String field : fields) {
            out.write('\t');
            out.write(clean(field));
        }
        out.newLine();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportGhidraAddressReferenceOwners.java <output.tsv> <address> [address ...]");
        }
        File output = new File(args[0]);
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();

        Listing listing = currentProgram.getListing();
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.write(HEADER);
            out.newLine();
            for (int i = 1; i < args.length; i++) {
                monitor.checkCancelled();
                Address target = toAddr(args[i]);
                MemoryBlock block = currentProgram.getMemory().getBlock(target);
                String targetBlock = block == null ? "-" : block.getName();
                String targetSymbol = symbolAt(target);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
                boolean any = false;
                while (refs.hasNext()) {
                    monitor.checkCancelled();
                    any = true;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function containing = currentProgram.getFunctionManager().getFunctionContaining(from);
                    Instruction instruction = listing.getInstructionAt(from);
                    writeRow(out,
                        target.toString(), targetBlock, targetSymbol,
                        from.toString(), ref.getReferenceType().toString(), ref.getSource().toString(),
                        Integer.toString(ref.getOperandIndex()), symbolAt(from),
                        instruction == null ? "-" : instruction.getMnemonicString(),
                        containing == null ? "-" : containing.getEntryPoint().toString(),
                        containing == null ? "-" : containing.getName(true));
                }
                if (!any) {
                    writeRow(out, target.toString(), targetBlock, targetSymbol,
                        "-", "-", "-", "-", "-", "-", "-", "-");
                }
            }
        }
        println("ADDRESS_REFERENCE_OWNERS_FORMAT=" + FORMAT);
        println("ADDRESS_REFERENCE_OWNERS_OUTPUT=" + output.getAbsolutePath());
    }
}
