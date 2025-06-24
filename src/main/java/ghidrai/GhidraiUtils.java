package ghidrai;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

/** Utility functions */
public class GhidraiUtils {
    // name of this extension e.g. "GhidrAI"
    public static final String THIS_EXTENSION_NAME =
            Application.getMyModuleRootDirectory().getName();

    public interface ProgramChangeListener {
        void onProgramChanged(Program program);
    }

    /**
     * Decompiles the given function and returns its {@link DecompiledFunction}, which includes
     * signatures and the content.
     *
     * @param function The function to decompile.
     * @param program The program to which the function belongs.
     * @return The {@link DecompiledFunction} object representing the decompiled function text.
     */
    public static DecompiledFunction getDecompiledFunctionText(Function function, Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        DecompileResults results = null;
        try {
            results = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        if (results != null && results.decompileCompleted()) {
            return results.getDecompiledFunction();
        }
        return null;
    }

    /**
     * Decompiles the given function and returns its {@link HighFunction}, which includes
     * signatures and the content.
     *
     * @param function The function to decompile.
     * @param program The program to which the function belongs.
     * @return The {@link HighFunction} object representing the decompiled function text.
     */
    public static HighFunction getDecompiledHighFunction(Function function, Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        DecompileResults results = null;
        try {
            results = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        if (results != null && results.decompileCompleted()) {
            return results.getHighFunction();
        }
        return null;
    }

    /**
     * Retrieves the assembly instructions for a given function as a text string.
     * <p>
     * This method iterates over the instructions in the body of the function and appends each to a
     * {@code StringBuilder} to create a single string representing the assembly instructions of the
     * function.
     *
     * @param function The function whose assembly text is to be retrieved.
     * @param program The program to which the function belongs.
     * @return A string representation of the assembly instructions for the given function.
     */
    public static String getAssemblyText(Function function, Program program) {
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        StringBuilder assemblyText = new StringBuilder();

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            assemblyText.append(instruction.toString() + "\n");
        }

        return assemblyText.toString();
    }

    /**
     * Determines if a function has a meaningful name.
     * <p>
     * A meaningful name is defined by several criteria:
     * <ul>
     * <li>The function has been renamed by the user</li>
     * <li>The function does not have a default Ghidra-generated name with the prefix
     * {@code "FUN_"}</li>
     * <li>The function's name follows the pattern of a valid identifier.</li>
     * </ul>
     *
     * @param function The function to check for a meaningful name.
     * @return {@code true} if the function has a meaningful name, {@code false} otherwise.
     */
    public static boolean isMeaningfulName(Function function) {
        String name = function.getName();
        return function.getSymbol().getSource() == SourceType.USER_DEFINED
                || (!name.startsWith("FUN_") && name.matches("[a-zA-Z_][a-zA-Z0-9_]*"));
    }

    public static void renameFunction(Program program, Function function,
            Map<String, String> renameMap) {
        int tid = program.startTransaction("Revise function");
        try {
            String oldName = function.getName();
            if (renameMap.containsKey(oldName)) {
                function.setName(renameMap.get(oldName), SourceType.ANALYSIS);
            }
            String comment = function.getComment();
            if(comment==null){
                comment = "";
            }
            for (Map.Entry<String, String> entry : renameMap.entrySet()) {
                comment = comment.replace(entry.getKey(), entry.getValue());
            }
            HighFunction hf = getDecompiledHighFunction(function, program);
            if (hf == null) {
                return;
            }
            LocalSymbolMap symMap = hf.getLocalSymbolMap();
            // Rename params.
            Parameter[] params = function.getParameters();
            for (Parameter param : params) {
                HighSymbol highsym = symMap.getParamSymbol(param.getOrdinal());
                String highName = highsym.getName();
                if (renameMap.containsKey(highName)) {
                    Msg.debug(GhidraiUtils.class, String.format("Rename params %s, %s", param.getName(), renameMap.get(highName)));
                    param.setName(renameMap.get(highName), SourceType.ANALYSIS);
                    renameMap.remove(highName);
                }
            }
            // Rename local variables. 
            // The decompiling may add non-existing variables to the symbol table.
            // But we can only automatically rename existing variables in original listings.
            Iterator<HighSymbol> symbols = symMap.getSymbols();
            Variable[] vars = function.getLocalVariables();
            Map<Variable, HighSymbol> v2s = new HashMap<>();
            while (symbols.hasNext()) {
                HighSymbol highsym = symbols.next();
                HighVariable highvar = highsym.getHighVariable();
                Varnode highnode = highvar.getRepresentative();
                String highName = highsym.getName();
                if(highnode==null){
                    Msg.debug(GhidraiUtils.class, String.format("High sym %s get null highnode", highName));
                }else{
                    Msg.debug(GhidraiUtils.class, String.format("=== High sym %s get %s", highName, highnode.getAddress()));
                }
                boolean found = false;
                for(Variable var: vars){
                    Varnode node = var.getFirstStorageVarnode();
                    if(node==null){
                        Msg.debug(GhidraiUtils.class, String.format("sym %s get null node", var.getName()));
                    }else{
                        Msg.debug(GhidraiUtils.class, String.format("sym %s get %s", var.getName(), node.getAddress()));
                    }
                    if(node.getAddress().equals(highnode.getAddress())) {
                        Msg.debug(GhidraiUtils.class, String.format("Rename var %s, %s", var.getName(), highName));
                        var.setName(renameMap.get(highName), SourceType.ANALYSIS);
                        renameMap.remove(highName);
                        found = true;
                        break;
                    }
                    if(found){
                        break;
                    }
                }
            }
            final String TEMPLATE = "Recommanded variable names:";
            // Add unchanged variable names to comment.
            comment = comment.replaceAll(TEMPLATE+"[\\s\\S]*", "");
            comment += TEMPLATE;
            comment += "\n";
            for (Map.Entry<String, String> entry : renameMap.entrySet()) {
                comment += String.format("%s -> %s\n", entry.getKey(), entry.getValue());
            }
            function.setComment(comment);
        } catch (Exception e) {
            Msg.error(GhidraiUtils.class,
                    String.format("Failed to rename function, %s", e.getMessage()));
        } finally {
            program.endTransaction(tid, true);
        }
    }

    public static void setComment(Program program, Function function, String comment) {
        int tid = program.startTransaction("Set Comment");
        try {
            function.setComment(comment);
        } catch (Exception e) {
            Msg.error(GhidraiUtils.class,
                    String.format("Failed to set comment for function, %s", e.getMessage()));
        } finally {
            program.endTransaction(tid, true);
        }
    }
}
