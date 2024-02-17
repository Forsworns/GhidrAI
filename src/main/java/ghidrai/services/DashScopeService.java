package ghidrai.services;

import org.python.antlr.ast.Return;

import com.alibaba.dashscope.aigc.generation.Generation;
import com.alibaba.dashscope.aigc.generation.GenerationParam;
import com.alibaba.dashscope.aigc.generation.GenerationParamBase;
import com.alibaba.dashscope.aigc.generation.GenerationResult;
import com.alibaba.dashscope.aigc.generation.models.QwenParam;
import com.alibaba.dashscope.common.Message;
import com.alibaba.dashscope.common.MessageManager;
import com.alibaba.dashscope.common.Role;
import com.alibaba.dashscope.exception.ApiException;
import com.alibaba.dashscope.exception.InputRequiredException;
import com.alibaba.dashscope.exception.NoApiKeyException;
import com.alibaba.dashscope.utils.JsonUtils;
import ghidra.util.Msg;

import ghidrai.GhidraiConfig;

public class DashScopeService implements ServiceInterface {
    /**
     * The service provider name.
     * <p>
     * Used to indicate the service provider. User can choose it in the {@code GhidrAIConfig.xml}.
     */
    private static final String NAME = "DashScope";
    // read this environment variable for authorization, same as the `API_KEY` in
    // the `GhidrAIConfig.xml`
    private static final String DASHSCOPE_KEY_ENV = "DASHSCOPE_API_KEY";
    private static final String apiKey;

    static {
        apiKey = System.getenv(DASHSCOPE_KEY_ENV);
        if (apiKey == null) {
            throw new IllegalStateException(String.format(
                    "DashScope API key must be set via environment variable. Try `export %s=YOUR_DASHSCOPE_API_KEY`.",
                    DASHSCOPE_KEY_ENV));
        }
        GhidraiConfig.addModels(NAME);
    }

    Generation gen;
    MessageManager msgManager;

    public DashScopeService() {
        gen = new Generation();
        msgManager = new MessageManager(10);
        Message systemMsg = Message.builder().role(Role.SYSTEM.getValue())
                .content(ServiceInterface.SYSTEM_PROMPT).build();
        msgManager.add(systemMsg);
    }

    public String chatWithBot(String template, String body)
            throws NoApiKeyException, ApiException, InputRequiredException {
        String model = GhidraiConfig.getModelName();
        GenerationParam param =
                GenerationParam.builder().model(model).messages(msgManager.get()).build();
        String prompt = String.format(template, body);
        param.setPrompt(prompt);
        GenerationResult result = this.gen.call(param);
        var output = result.getOutput();
        if (output == null) {
            return null;
        }
        Msg.debug(this, "LLM response is \n" + output.getText());
        return output.getText();
    }

    @Override
    public String explainFunction(String body) throws Exception {
        return chatWithBot(ServiceInterface.EXPLAIN_PROMPT_TEMPLATE, body);
    }

    @Override
    public String renameFunction(String body) throws Exception {
        return chatWithBot(ServiceInterface.RENAME_PROMPT_TEMPLATE, body);
    }

    @Override
    public String fixJson(String s) throws Exception {
        return chatWithBot(ServiceInterface.JSON_PROMPT_TEMPLATE, s);
    }

    @Override
    public String getName() {
        return NAME;
    }
}
