package ghidrai;

import java.util.Map;

import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import ghidrai.services.GhidraiAgent;

/**
 * The anaylzer plugin to enable global analysis.
 */
public class GhidraiAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "GhidrAI";
    private static final String DESCRIPTION = "AI assisted analysis";
    private static final String OPTION_NAME_DECOMPILE = "Decompile before analysis";
    private static final String OPTION_DESCRIPTION_DECOMPILE =
            "Decompile before requests LLM services. It helps the LLM analyzes program but further increasing time cost.";

    private GhidraiAgent agent = null;
    private boolean decompileEnabled = false;

    public GhidraiAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_SIGNATURES_ANALYZER);
        // we want to revise the signature after the `FUNCTION_ANALYSIS`, before the
        // `DATA_TYPE_PROPOGATION`
        super.setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
        agent = new GhidraiAgent();
        setDefaultEnablement(false);
        setSupportsOneTimeAnalysis();
        Msg.debug(this, "The GhidraiAnalyzer is loaded.");
    }

    @Override
    public boolean canAnalyze(Program program) {
        return agent != null;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (this.agent == null) {
            return false;
        }
        this.agent.setupServiceProvider();
        if (this.agent.isServiceProviderNull()) {
            return false;
        }

        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(set, true);

        while (functions.hasNext()) {
            if (monitor.isCancelled()) {
                throw new CancelledException("User cancelled analysis");
            }

            Function function = functions.next();
            if (GhidraiUtils.isMeaningfulName(function)) {
                continue;
            }
            String body = null;

            if (GhidraiConfig.getEnableDecompile()) {
                DecompiledFunction decompiledFunc =
                        GhidraiUtils.getDecompiledFunctionText(function, program);
                body = decompiledFunc.getC();
            } else {
                body = GhidraiUtils.getAssemblyText(function, program);
            }

            Map<String, String> newName = agent.renameFunction(body);
            if (newName == null) {
                continue;
            }
            GhidraiUtils.renameFunction(program, function, newName);

            String comment = agent.explainFunction(body);
            if (comment == null) {
                continue;
            }
            GhidraiUtils.setComment(program, function, comment);
        }

        return true;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        decompileEnabled = GhidraiConfig.getEnableDecompile();
        options.registerOption(OPTION_NAME_DECOMPILE, decompileEnabled, null,
                OPTION_DESCRIPTION_DECOMPILE);
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        decompileEnabled = options.getBoolean(OPTION_NAME_DECOMPILE, decompileEnabled);
        GhidraiConfig.setEnableDecompile(decompileEnabled);
        GhidraiConfig.save();
    }
}
