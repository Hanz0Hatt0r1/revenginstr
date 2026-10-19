import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;

/** Create one exact function entry in an explicitly writable project copy. */
public class SeedFunctionAtAddress extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Usage: SeedFunctionAtAddress.java <function-entry>");
        }

        Address entry = toAddr(args[0]);
        Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
        if (instruction == null) {
            throw new IllegalArgumentException("Requested function entry is not an instruction: " + entry);
        }

        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionAt(entry);
        if (function == null) {
            Function containing = functions.getFunctionContaining(entry);
            if (containing != null) {
                throw new IllegalStateException(
                    "Requested entry is inside existing function " + containing.getEntryPoint());
            }

            CreateFunctionCmd command = new CreateFunctionCmd(entry);
            if (!command.applyTo(currentProgram, monitor)) {
                throw new IllegalStateException("CreateFunctionCmd failed: " + command.getStatusMsg());
            }
            function = command.getFunction();
        }

        if (function == null || !function.getEntryPoint().equals(entry)) {
            throw new IllegalStateException("Created function entry does not match request");
        }
        println("GHIDRA_SEEDED_FUNCTION_ENTRY=" + function.getEntryPoint());
        println("GHIDRA_SEEDED_FUNCTION_BODY_BYTES=" + function.getBody().getNumAddresses());
    }
}
