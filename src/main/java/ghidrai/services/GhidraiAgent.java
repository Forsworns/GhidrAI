package ghidrai.services;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.util.Msg;

import ghidrai.GhidraiConfig;

/**
 * GhidrAI's agent class, to delegate the real generation requests.
 */
public class GhidraiAgent {
    // here we can safely assume that only a single request will be handled in an
    // agent, because we use `TaskLauncher.launchModal` in `GhidraiActions`,
    // no need to consider cocurrent problems.
    private ServiceInterface serviceProvider = null;
    private Gson gson = null;
    Type NamesMapType = new TypeToken<Map<String, String>>() {}.getType();

    private static HashMap<String, Class<?>> spClsMap = new HashMap<>();
    private HashMap<String, ServiceInterface> spMap = new HashMap<>();

    static {
        ServiceLoader<ServiceInterface> loader = ServiceLoader.load(ServiceInterface.class);
        for (ServiceInterface service : loader) {
            try {
                spClsMap.put(service.getName(), service.getClass());
                Msg.debug(GhidraiAgent.class,
                        String.format("Service provider %s gets registered", service.getName()));
            } catch (Exception e) {
                Msg.error(GhidraiAgent.class,
                        String.format("Failed to register service provider, %s", e.getMessage()));
            }
        }
    }

    public GhidraiAgent() {
        setupServiceProvider();
        gson = new Gson();
    }

    public boolean isServiceProviderNull() {
        return serviceProvider == null;
    }

    public void setupServiceProvider() {
        String spKey = GhidraiConfig.getServiceProvider();
        if (spMap.containsKey(spKey)) {
            serviceProvider = spMap.get(spKey);
        } else {
            var spCls = spClsMap.get(spKey);
            try {
                serviceProvider = (ServiceInterface) spCls.getDeclaredConstructor().newInstance();
                spMap.put(spKey, serviceProvider);
                Msg.debug(this,
                        String.format("Succeed to initialize service provider, %s", spKey));
            } catch (Exception e) {
                Msg.error(this,
                        String.format("Failed to initialize service provider, %s", e.getMessage()));
            }
        }
    }

    public String explainFunction(String body) {
        setupServiceProvider();
        if (serviceProvider == null) {
            Msg.error(this, "explainFunction: No service provider is set");
            return null;
        }
        int times = 0;
        Msg.debug(this, String.format("GhidrAI explainFunction request(%d) ...", times));
        while (times < GhidraiConfig.getRetryTimes()) {
            try {
                return this.serviceProvider.explainFunction(body);
            } catch (Exception e) {
                times++;
                Msg.error(this, String.format("Failed to request(%d), %s", times, e.getMessage()));
            }
        }
        return null;
    }

    public Map<String, String> renameFunction(String body) {
        setupServiceProvider();
        if (serviceProvider == null) {
            Msg.error(this, "explainFunction: No service provider is set");
            return null;
        }
        int times = 0;
        Msg.debug(this, String.format("GhidrAI renameFunction request(%d) ...", times));
        String namesJson = null;
        Map<String, String> names = null;
        while (times < GhidraiConfig.getRetryTimes()) {
            try {
                namesJson = this.serviceProvider.renameFunction(body);
                int startIndex = namesJson.indexOf('{');
                int endIndex = namesJson.lastIndexOf('}');
                if (startIndex != -1 && endIndex != -1) {
                    namesJson = namesJson.substring(startIndex, endIndex + 1);
                    break;
                }
            } catch (Exception e) {
                Msg.error(this, String.format("Failed to request(%d), %s", times, e.getMessage()));
                times++;
            }

        }
        if (namesJson == null) {
            return null;
        }
        times = 0;
        while (times < GhidraiConfig.getRetryTimes()) {
            try {
                int start = namesJson.indexOf('{');
                int end = namesJson.lastIndexOf('}');
                if (start != -1 && end != -1 && end > start) {
                    namesJson = namesJson.substring(start, end + 1);
                }
                names = gson.fromJson(namesJson, NamesMapType);
                return names;
            } catch (Exception e1) {
                times++;
                Msg.error(this,
                        String.format("Failed to parse json (%d), %s", times, e1.getMessage()));
                try {
                    namesJson = this.serviceProvider.fixJson(namesJson);
                } catch (Exception e2) {
                    Msg.error(this, String.format("Failed to request json fix (%d), %s", times,
                            e1.getMessage()));
                }
            }
        }
        return null;
    }
}
