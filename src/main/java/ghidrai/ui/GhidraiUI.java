package ghidrai.ui;

import java.awt.event.KeyEvent;
import java.util.Map;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.services.CodeViewerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

import ghidrai.GhidraiPlugin;
import ghidrai.GhidraiUtils;
import ghidrai.GhidraiUtils.ProgramChangeListener;
import ghidrai.services.GhidraiAgent;

public class GhidraiUI implements ProgramChangeListener {
    private GhidraiAgent agent;
    private CodeViewerService codeViewer;
    private Program program;

    public GhidraiUI(GhidraiPlugin plugin) {
        agent = new GhidraiAgent();
        codeViewer = plugin.getTool().getService(CodeViewerService.class);
        program = plugin.getProgram();
        plugin.addProgramChangeListener(this);

        // setup rename function
        DockingAction rename = new DockingAction("Rename Function", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                renameFunction();
            }
        };
        rename.setPopupMenuData(new MenuData(new String[] {"GhidrAI", "Rename"}));
        rename.setKeyBindingData(
                new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_L, KeyEvent.ALT_DOWN_MASK)));
        plugin.getTool().addAction(rename);

        // setup explain function
        DockingAction explain = new DockingAction("Explain Function", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                explainFunction();
            }
        };
        explain.setPopupMenuData(new MenuData(new String[] {"GhidrAI", "Explain"}));
        explain.setKeyBindingData(new KeyBindingData(
                KeyStroke.getKeyStroke(KeyEvent.VK_SEMICOLON, KeyEvent.ALT_DOWN_MASK)));
        plugin.getTool().addAction(explain);

        // setup configuration
        DockingAction config = new DockingAction("Configuration", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                plugin.getTool().showDialog(new GhidraiDialog());
            }
        };
        config.setMenuBarData(new MenuData(new String[] {"Tools", "GhidrAI"}));
        config.setToolBarData(null); // Set toolbar data if needed
        config.setDescription("Select the model for the plugin");
        config.setHelpLocation(new HelpLocation("YourPluginName", "select_model"));
        plugin.getTool().addAction(config);
    }


    @Override
    public void onProgramChanged(Program program) {
        this.program = program;
    }

    private Function getSelectedFunction() {
        ProgramSelection selection = this.codeViewer.getCurrentSelection();
        if (selection == null || selection.isEmpty()) {
            return null;
        }
        Address start = selection.getMinAddress();
        FunctionManager functionManager = this.program.getFunctionManager();
        Function function = functionManager.getFunctionAt(start);
        return function;
    }

    private void renameFunction() {
        TaskLauncher.launchModal("GhidrAI request rename...", () -> {
            Function function = getSelectedFunction();
            if (function == null) {
                return;
            }
            DecompiledFunction decompiledFunc =
                    GhidraiUtils.getDecompiledFunctionText(function, this.program);
            String body = decompiledFunc.getC();
            Map<String, String> names = this.agent.renameFunction(body);
            if (names == null) {
                return;
            }
            GhidraiUtils.renameFunction(this.program, function, names);
        });
    }

    private void explainFunction() {
        TaskLauncher.launchModal("GhidrAI request explain...", () -> {
            Function function = getSelectedFunction();
            if (function == null) {
                return;
            }
            DecompiledFunction decompiledFunc =
                    GhidraiUtils.getDecompiledFunctionText(function, this.program);
            String body = decompiledFunc.getC();
            String comment = this.agent.explainFunction(body);
            if (comment == null) {
                return;
            }
            GhidraiUtils.setComment(this.program, function, comment);
        });
    }
}
