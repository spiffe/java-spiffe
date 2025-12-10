package io.spiffe.helper.cli;

import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper.KeyStoreOptions;
import io.spiffe.helper.keystore.KeyStoreType;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

class Config {

    private static final String DEFAULT_CONFIG_FILENAME = "conf/java-spiffe-helper.properties";

    static final Option CONFIG_FILE_OPTION =
            Option.builder("c")
                    .longOpt("config")
                    .hasArg(true)
                    .required(false)
                    .build();

    private Config() {
    }

    static Properties parseConfigFileProperties(final Path configFilePath) throws RunnerException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(configFilePath)) {
            properties.load(in);
        } catch (IOException e) {
            String error = String.format("Cannot open config file: %s", configFilePath);
            throw new RunnerException(error, e);
        }
        return properties;
    }

    static String getCliConfigOption(final String... args) throws ParseException {
        final Options cliOptions = new Options();
        cliOptions.addOption(CONFIG_FILE_OPTION);
        CommandLineParser parser = new DefaultParser();

        CommandLine cmd = parser.parse(cliOptions, args);
        return cmd.getOptionValue("config", getDefaultConfigPath());
    }

    private static String getDefaultConfigPath() {
        return Paths.get(System.getProperty("user.dir"), DEFAULT_CONFIG_FILENAME).toString();
    }

    static KeyStoreOptions createKeyStoreOptions(Properties properties) {
        String keyStorePath = getProperty(properties, "keyStorePath");
        String keyStorePass = getProperty(properties, "keyStorePass");
        String keyPass = getProperty(properties, "keyPass");
        String trustStorePath = getProperty(properties, "trustStorePath");
        String trustStorePass = getProperty(properties, "trustStorePass");

        String keyAlias = properties.getProperty("keyAlias", null);
        String spiffeSocketPath = properties.getProperty("spiffeSocketPath", null);
        String keyStoreTypeProp = properties.getProperty("keyStoreType", null);

        KeyStoreType keyStoreType;
        if (StringUtils.isNotBlank(keyStoreTypeProp)) {
            keyStoreType = KeyStoreType.parse(keyStoreTypeProp);
        } else {
            keyStoreType = KeyStoreType.getDefaultType();
        }

        return KeyStoreOptions.builder()
                .keyStorePath(Paths.get(keyStorePath))
                .keyStorePass(keyStorePass)
                .keyPass(keyPass)
                .trustStorePath(Paths.get(trustStorePath))
                .trustStorePass(trustStorePass)
                .keyAlias(keyAlias)
                .spiffeSocketPath(spiffeSocketPath)
                .keyStoreType(keyStoreType)
                .build();

    }

    static String getProperty(Properties properties, String key) {
        final String value = properties.getProperty(key);
        if (StringUtils.isBlank(value)) {
            throw new IllegalArgumentException(String.format("Missing value for config property: %s", key));
        }
        return value;
    }
}
