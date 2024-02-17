package ghidrai.ui;

import java.awt.*;
import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;

import ghidrai.GhidraiConfig;

public class GhidraiDialog extends DialogComponentProvider {
    private JComboBox<String> modelComboBox;
    private JTextField serviceProviderTextField;
    private JTextField apiKeyTextField;
    private JSpinner retryTimesSpinner;
    private JCheckBox enableDecompileCheckBox;
    private JSpinner decompileTimeoutSpinner;

    public GhidraiDialog() {
        super("GhidrAI");
        init();
    }

    private void init() {
        initPanel();
        addOKButton();
        addCancelButton();
        resetPanel();
    }

    private void initPanel() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        mainPanel.add(createLabeledComponent("Service Provider:",
                serviceProviderTextField = new JTextField(20)));
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        mainPanel.add(createLabeledComponent("Select a model:", modelComboBox =
                new JComboBox<String>(GhidraiConfig.getModels().toArray(new String[0]))));
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        mainPanel.add(createLabeledComponent("API Key:", apiKeyTextField = new JTextField(20)));
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        mainPanel.add(createLabeledComponent("Retry Times:", retryTimesSpinner =
                new JSpinner(new SpinnerNumberModel(1, 0, Integer.MAX_VALUE, 1))));
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        mainPanel.add(createCheckboxComponent("Enable Decompile:",
                enableDecompileCheckBox = new JCheckBox()));
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        mainPanel.add(
                createLabeledComponent("Decompile Timeout (seconds):", decompileTimeoutSpinner =
                        new JSpinner(new SpinnerNumberModel(30, 1, Integer.MAX_VALUE, 1))));

        addWorkPanel(mainPanel);
    }

    private JPanel createLabeledComponent(String label, JComponent component) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel(label), BorderLayout.WEST);
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createCheckboxComponent(String label, JCheckBox checkBox) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel(label), BorderLayout.WEST);
        panel.add(checkBox, BorderLayout.CENTER);
        return panel;
    }

    private void resetPanel() {
        serviceProviderTextField.setText(GhidraiConfig.getServiceProvider());
        modelComboBox.setSelectedItem(GhidraiConfig.getModelName());
        apiKeyTextField.setText(GhidraiConfig.getApiKey());
        retryTimesSpinner.setValue(GhidraiConfig.getRetryTimes());
        enableDecompileCheckBox.setSelected(GhidraiConfig.getEnableDecompile());
        decompileTimeoutSpinner.setValue(GhidraiConfig.getDecompileTimeout());
    }


    @Override
    protected void okCallback() {
        String selectedModel = modelComboBox.getSelectedItem() == null ? ""
                : (String) modelComboBox.getSelectedItem();
        GhidraiConfig.setServiceProvider(serviceProviderTextField.getText());
        GhidraiConfig.setModelName(selectedModel);
        GhidraiConfig.setApiKey(apiKeyTextField.getText());
        GhidraiConfig.setRetryTimes((Integer) retryTimesSpinner.getValue());
        GhidraiConfig.setEnableDecompile(enableDecompileCheckBox.isSelected());
        GhidraiConfig.setDecompileTimeout((Integer) decompileTimeoutSpinner.getValue());
        GhidraiConfig.save();
        close();
    }

    @Override
    protected void cancelCallback() {
        resetPanel();
        close();
    }

    // 显示对话框
    void showDialog() {
        DockingWindowManager.showDialog(null, this);
    }
}
