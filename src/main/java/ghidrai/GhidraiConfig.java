package ghidrai;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;

import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.util.Msg;

/**
 * GhidrAI's configuration class, an eager singleton
 */
public class GhidraiConfig {
  private static GhidraiConfig CONFIG = new GhidraiConfig();

  private static final int DEFAULT_RETRY_TIMES = 3;
  private static final int DEFAULT_DECOMPILE_TIMEOUT = 30;
  private static final String DEFAULT_CONFIG_FILENAME = "GhidraiConfig.xml";
  private static final String SERVICE_PROVIDER_KEY = "SERVICE_PROVIDER";
  private static final String MODEL_NAME_KEY = "MODEL_NAME";
  private static final String API_KEY_KEY = "API_KEY";
  private static final String RETRY_TIMES_KEY = "RETRY_TIMES";
  private static final String ENABLE_DECOMPILE_KEY = "ENABLE_DECOMPILE";
  private static final String DECOMPILE_TIMEOUT_KEY = "DECOMPILE_TIMEOUT";

  private String serviceProvider = "";
  private String modelName = "";
  private String apiKey = "";
  private int retryTimes = DEFAULT_RETRY_TIMES;
  private boolean enableDecompile = false;
  // timeout in seconds
  private int decompile_timeout = DEFAULT_DECOMPILE_TIMEOUT;
  private Map<String, Set<String>> models = new HashMap<>();
  private SaveState state = null;

  /**
   * Retrieves the service provider from configuration.
   * <p>
   * The value is specified by the {@link #SERVICE_PROVIDER_KEY} in the {@code GhidrAIConfig.xml},
   * used to select a service provider.
   *
   * @return The service provider as a {@code String}.
   */
  public static String getServiceProvider() {
    return CONFIG.serviceProvider;
  }

  /**
   * Retrieves the model name from configuration.
   * <p>
   * Optional: The value is specified by the {@link #MODEL_NAME_KEY} in the
   * {@code GhidrAIConfig.xml}. Some service providers supply several models. The chosen model must
   * be listed in the models of corresponding service provider.
   *
   * @return The model name as a {@code String}.
   */
  public static String getModelName() {
    Set<String> models = CONFIG.models.getOrDefault(CONFIG.serviceProvider, Collections.emptySet());
    return models.contains(CONFIG.modelName) ? CONFIG.modelName : "";
  }

  /**
   * Retrieves the supportd model lists of the given service provider from configuration.
   * <p>
   * Optional: The value is configured as an array with the service provider name, e.g.,
   * {@link ghidrai.services.DashScopeService#DASHSCOPE_NAME} in the {@code GhidrAIConfig.xml}.
   *
   * @return The supported models for given {@link #serviceProvider}.
   */
  public static Set<String> getModels() {
    return CONFIG.models.getOrDefault(CONFIG.serviceProvider, Collections.emptySet());
  }

  /**
   * Retrieves the API key from configuration.
   * <p>
   * Optional: The value is specified by the {@link #API_KEY_KEY} in the {@code GhidrAIConfig.xml},
   * used for authorization. Some service providers read it from the environment variable.
   *
   * @return The API key as a {@code String}.
   */
  public static String getApiKey() {
    return CONFIG.apiKey;
  }

  /**
   * Retrieves the number of retry attempts from configuration.
   * <p>
   * Optional: The default is {@link #DEFAULT_RETRY_TIMES}. The value is specified by the
   * {@link #RETRY_TIMES_KEY} in the {@code GhidrAIConfig.xml}, used to control the request retry
   * times.
   *
   * @return The number of retry times as an {@code int}.
   */
  public static int getRetryTimes() {
    return CONFIG.retryTimes;
  }

  /**
   * Retrieves the decompiling enable status from configuration.
   * <p>
   * Optional: The default is {@code false}. The value is specified by the
   * {@link #ENABLE_DECOMPILE_KEY} in the {@code GhidrAIConfig.xml}, used to enable decompiling for
   * analysis in {@link ghidrai.GhiraiAnalyzer}. The {@link ghidrai.GhidraiAction} always enables
   * decompiling.
   *
   * @return {@code true} if decompiling is enabled, {@code false} otherwise.
   */
  public static boolean getEnableDecompile() {
    return CONFIG.enableDecompile;
  }

  /**
   * Retrieves the decompiling timeout setting.
   * <p>
   * This value is optional. If not set, the default value is used, which is specified by the
   * {@link #DEFAULT_DECOMPILE_TIMEOUT} constant. The setting can be controlled by specifying the
   * {@link #DECOMPILE_TIMEOUT_KEY} in the {@code GhidrAIConfig.xml} file.
   *
   * @return The timeout duration in seconds for decompiling operations.
   */
  public static int getDecompileTimeout() {
    return CONFIG.decompile_timeout;
  }

  public static void setServiceProvider(String serviceProvider) {
    CONFIG.serviceProvider = serviceProvider;
    CONFIG.state.putString(SERVICE_PROVIDER_KEY, serviceProvider);
  }

  public static void setModelName(String modelName) {
    CONFIG.modelName = modelName;
    CONFIG.state.putString(MODEL_NAME_KEY, modelName);
  }

  public static void setApiKey(String apiKey) {
    CONFIG.apiKey = apiKey;
    CONFIG.state.putString(API_KEY_KEY, apiKey);
  }

  public static void setRetryTimes(int retryTimes) {
    CONFIG.retryTimes = retryTimes;
    CONFIG.state.putInt(RETRY_TIMES_KEY, retryTimes);
  }

  public static void setEnableDecompile(boolean enableDecompile) {
    CONFIG.enableDecompile = enableDecompile;
    CONFIG.state.putBoolean(ENABLE_DECOMPILE_KEY, enableDecompile);
  }

  public static void setDecompileTimeout(int decompileTimeout) {
    CONFIG.decompile_timeout = decompileTimeout;
    CONFIG.state.putInt(DECOMPILE_TIMEOUT_KEY, decompileTimeout);
  }

  public static void addModels(String serviceProvider) {
    var models =
        new HashSet<String>(Arrays.asList(CONFIG.state.getStrings(serviceProvider, new String[0])));
    CONFIG.models.put(serviceProvider, models);
  }

  public static void save() {
    try {
      CONFIG.state
          .saveToXmlFile(new File(Application.getUserSettingsDirectory(), DEFAULT_CONFIG_FILENAME));
    } catch (IOException e) {
      Msg.error(CONFIG,
          String.format("Failed to save the configuration to the file, %s", e.getMessage()));
    }
  }

  /**
   * Get GhidrAI's default configuration - default configuration is stored in
   * {@code data/GhidrAIConfig.xml} and copied to Ghidra user settings directory when first
   * accessed.
   */
  private GhidraiConfig() {
    File userSettingsPath =
        new File(Application.getUserSettingsDirectory(), DEFAULT_CONFIG_FILENAME);

    // copy configuration from /data to Ghidra user settings if file does not
    // already exist
    if (!userSettingsPath.isFile()) {

      Msg.info(this, "Addings configuration to user settings at " + userSettingsPath);

      try {

        File dataPath =
            Application.getModuleDataFile(GhidraiUtils.THIS_EXTENSION_NAME, DEFAULT_CONFIG_FILENAME)
                .getFile(false);
        Files.copy(dataPath.toPath(), userSettingsPath.toPath(),
            StandardCopyOption.REPLACE_EXISTING);

      } catch (IOException e) {

        Msg.error(this, "Failed to write user configuration [" + e + "]");
        return;
      }
    }

    state = null;

    // attempt to read configuration from Ghidra user settings
    try {

      state = new SaveState(userSettingsPath);

    } catch (IOException e) {

      Msg.error(this, "Failed to read configuration state [" + e + "]");
      return;
    }

    String serviceProvider = state.getString(SERVICE_PROVIDER_KEY, "");
    if (!serviceProvider.isEmpty()) {
      this.serviceProvider = serviceProvider;
    }

    String modelName = state.getString(MODEL_NAME_KEY, "");
    if (!modelName.isEmpty()) {
      this.modelName = modelName;
    }

    String apiKey = state.getString(API_KEY_KEY, "");
    if (!apiKey.isEmpty()) {
      this.apiKey = apiKey;
    }

    this.retryTimes = state.getInt(RETRY_TIMES_KEY, DEFAULT_RETRY_TIMES);
    this.enableDecompile = state.getBoolean(ENABLE_DECOMPILE_KEY, false);
    this.decompile_timeout = state.getInt(DECOMPILE_TIMEOUT_KEY, DEFAULT_DECOMPILE_TIMEOUT);
  }
}
