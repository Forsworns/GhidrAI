package ghidrai.services;

/**
 * for each service provider, implement this interface
 */
public interface ServiceInterface {
        public final String SYSTEM_PROMPT = "You are a helpful assistant for reverse engineering.";

        public final String EXPLAIN_PROMPT_TEMPLATE =
                        "Can you explain what the following C function does "
                                        + "and suggest a better name for it?\n%s";

        public final String RENAME_PROMPT_TEMPLATE = "Analyze the following C function:\n%s\n"
                        + "Suggest better variable names, reply with a Java Gson JSON map, "
                        + "where keys are the original names, and values are the proposed names. "
                        + "Do not explain anything, only print the JSON map.";

        public final String JSON_PROMPT_TEMPLATE =
                        "The JSON array provided in this response is in invalid format."
                                        + "Can you fix it without changing the key and value?\n%s";

        /**
         * Attempts to explain the usage of a function.
         * <p>
         * This method should use {@link String#format()} to construct a complete prompt by
         * combining the given function body with the {@link #EXPLAIN_PROMPT_TEMPLATE}.
         *
         * @param body The body of the function to be explained.
         * @return An explanation of the function's usage.
         * @throws Exception if there is an error during the process.
         */
        String explainFunction(String body) throws Exception;

        /**
         * Attempts to rename a function.
         * <p>
         * This method should use {@link String#format()} to construct a complete prompt by
         * combining the given function body with the {@link #RENAME_PROMPT_TEMPLATE}.
         *
         * @param body The body of the function to be renamed.
         * @return A suggested new name for the name and variables in function.
         * @throws Exception if there is an error during the process.
         */
        String renameFunction(String body) throws Exception;

        /**
         * Attempts to fix a json string.
         * <p>
         * This method should use {@link String#format()} to construct a complete prompt by
         * combining the given json string with the {@link #JSON_PROMPT_TEMPLATE}.
         *
         * @param s The json string.
         * @return A fixed json string.
         * @throws Exception if there is an error during the process.
         */

        String fixJson(String s) throws Exception;

        /**
         * Service provider name.
         *
         * @return The name must be the same as the name returned in
         *         {@link ghidrai.GhidraiConfig#getServiceProvider}.
         */
        String getName();
}
