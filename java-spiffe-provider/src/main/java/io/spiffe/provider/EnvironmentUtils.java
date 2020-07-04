package io.spiffe.provider;

import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.security.Security;

/**
 * Utility class to get value from the environment.
 */
final class EnvironmentUtils {

    private EnvironmentUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Looks for a variable name defined in the environment.
     * It first looks in the {@link Security} environment, if it is not defined or is a blank value,
     * it looks in the {@link System}  environment, if it is not defined or is a blank value,
     * returns the defaultValue.
     * @param variableName the key of the variable to look for in the environment
     * @param defaultValue the value that is returned if the variable has no value in the environment
     * @return a String with a value
     */
    static String getProperty(final String variableName, final String defaultValue) {
        val value = getProperty(variableName);
        if (StringUtils.isNotBlank(value)) {
            return value;
        }

        return defaultValue;
    }

    /**
     * Looks for a variable name defined in the environment.
     * It first looks in the {@link Security} environment, if it is not defined or is a blank value,
     * it looks in the {@link System} environment.
     * @param variableName the key of the variable to look for in the environment
     * @return a String with a value
     */
    static String getProperty(final String variableName) {
        String value;
        value = Security.getProperty(variableName);
        if (StringUtils.isNotBlank(value)) {
            return value;
        }
        value = System.getProperty(variableName);
        if (StringUtils.isNotBlank(value)) {
            return value;
        }
        return "";
    }
}
