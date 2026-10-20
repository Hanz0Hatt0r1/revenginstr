import ghidra.app.plugin.core.analysis.DecompilerFunctionAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// Explicit write step: persist Ghidra's recovered signatures before read-only exports.
public class ApplyDecompilerParameterId extends GhidraScript {
    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private Function resolveFunction(String token) throws Exception {
        String addressText = token.startsWith("0x") || token.startsWith("0X")
            ? token.substring(2) : token;
        Address address = toAddr(addressText);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) throw new IllegalArgumentException("Function entry not found: " + token);
        return function;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException(
                "Usage: ApplyDecompilerParameterId.java <function-entry> [function-entry ...]");
        }

        List<Function> functions = new ArrayList<>();
        Set<Address> seen = new HashSet<>();
        for (String token : args) {
            monitor.checkCancelled();
            Function function = resolveFunction(token.trim());
            if (seen.add(function.getEntryPoint())) functions.add(function);
        }

        setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
        Analyzer analyzer = new DecompilerFunctionAnalyzer();
        for (Function function : functions) {
            monitor.checkCancelled();
            String before = function.getSignature().toString();
            analyzer.added(currentProgram, function.getBody(), monitor, new MessageLog());
            String after = function.getSignature().toString();
            println("GHIDRA_PARAMETER_ID_FUNCTION=" + cell(function.getEntryPoint()));
            println("GHIDRA_PARAMETER_ID_SIGNATURE_BEFORE=" + cell(before));
            println("GHIDRA_PARAMETER_ID_SIGNATURE_AFTER=" + cell(after));
        }
        println("GHIDRA_PARAMETER_ID_FUNCTION_COUNT=" + functions.size());
        println("GHIDRA_PARAMETER_ID_COMPLETE=true");
    }
}
