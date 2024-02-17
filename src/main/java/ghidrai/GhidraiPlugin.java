package ghidrai;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import ghidrai.GhidraiUtils.ProgramChangeListener;
import ghidrai.ui.GhidraiUI;

// @formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Boost Ghidra with LLM",
    description = "Use state of the art large language model to boost reverse engineering")
// @formatter:on

public class GhidraiPlugin extends ProgramPlugin {
  private List<ProgramChangeListener> listeners = new ArrayList<>();

  public GhidraiPlugin(PluginTool tool) {
    super(tool);
  }

  @Override
  public void init() {
    super.init();
    try {
      new GhidraiUI(this);
    } catch (Exception e) {
      Msg.error(this, String.format("Failed to initialize the GhidraiPlugin %s", e.getMessage()));
    }
  }

  // `currentProgram` is a protected variable in `ProgramPlugin`
  public Program getProgram() {
    return currentProgram;
  }

  public void addProgramChangeListener(ProgramChangeListener listener) {
    listeners.add(listener);
  }

  @Override
  protected void programActivated(Program program) {
    super.programActivated(program);
    for (ProgramChangeListener listener : listeners) {
      listener.onProgramChanged(currentProgram);
    }
  }
}
