The "data" directory is intended to hold data files that will be used by this module and will not end up in the .jar file, but will be present in the zip or tar file.  Typically, data files are placed here rather than in the resources directory if the user may need to edit them.

The data/GhidrAIConfig.xml is used to configure the GhidrAI plugin. The configurable items are introduced as following:

Item | Default | Meaning |
|---|---|---|
| `SERVICE_PROVIDER` | `DashScope` | The LLM service provider: DashScope, OpenAI (Help Wanted). |
| `MODEL_NAME` | `qwen-max` | The model of provider: <ul><li>DashScope (Free models: qwen-max, qwen-max-longcontext, baichuan-7b-v1, llama2-7b-chat-v2, llama2-13b-chat-v2, chatglm3-6b)</li> <li>OpenAI (Help Wanted)</li></ul>    |
| `API_KEY` | `""` | The API key from your service provider. |
| `RETRY_TIMES` | `3` | Retry serveral times when failed. |
| `ENABLE_DECOMPILE` | `true` | Whether decompile before request analysis, which only applies to GhidraiAnalyzer, for UI interaction, the assembly is alway decompiled. |
| `DECOMPILE_TIMEOUT` | `30` | The timeout for decompiler. |