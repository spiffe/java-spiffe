package io.spiffe.helper.cli;

import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper.KeyStoreOptions;
import io.spiffe.helper.keystore.KeyStoreType;
import lombok.val;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.util.Properties;

class Config {

    static final Option CONFIG_FILE_OPTION =
            Option.builder("c")
            .longOpt("config")
            .hasArg(true)
            .required(true)
            .build();

    private Config() {
    }

    static Properties parseConfigFileProperties(final Path configFilePath) throws RunnerException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(configFilePath)) {
            properties.load(in);
        } catch (IOException e) {
            val error = String.format("Cannot open config file: %s", configFilePath);
            throw new RunnerException(error, e);
        }
        return properties;
    }

    static String getCliConfigOption(final String... args) throws RunnerException {
        final Options cliOptions = new Options();
        cliOptions.addOption(CONFIG_FILE_OPTION);
        CommandLineParser parser = new DefaultParser();
        try {
            val cmd = parser.parse(cliOptions, args);
            return cmd.getOptionValue("config");
        } catch (ParseException e) {
            val error = String.format("%s. Use -c, --config <arg>", e.getMessage());
            throw new RunnerException(error);
        }
    }

    static KeyStoreOptions createKeyStoreOptions(final Properties properties) {
        val keyStorePath = getProperty(properties, "keyStorePath");
        val keyStorePass = getProperty(properties, "keyStorePass");
        val keyPass = getProperty(properties, "keyPass");
        val trustStorePath = getProperty(properties, "trustStorePath");
        val trustStorePass = getProperty(properties, "trustStorePass");

        val includeRootCaCertProp = properties.getProperty("includeRootCaCertInChain", "false");
        val keyAlias = properties.getProperty("keyAlias", null);
        val spiffeSocketPath = properties.getProperty("spiffeSocketPath", null);
        val keyStoreTypeProp = properties.getProperty("keyStoreType", null);

        KeyStoreType keyStoreType;
        if (StringUtils.isNotBlank(keyStoreTypeProp)) {
            keyStoreType = KeyStoreType.parse(keyStoreTypeProp);
        } else {
            keyStoreType = KeyStoreType.getDefaultType();
        }

        val includeRootCaCert = Boolean.parseBoolean(includeRootCaCertProp);

        return KeyStoreOptions.builder()
                .keyStorePath(Paths.get(keyStorePath))
                .keyStorePass(keyStorePass)
                .keyPass(keyPass)
                .trustStorePath(Paths.get(trustStorePath))
                .trustStorePass(trustStorePass)
                .keyAlias(keyAlias)
                .includeRootCaCertInChain(includeRootCaCert)
                .spiffeSocketPath(spiffeSocketPath)
                .keyStoreType(keyStoreType)
                .build();

    }

    static String getProperty(final Properties properties, final String key) {
        final String value = properties.getProperty(key);
        if (StringUtils.isBlank(value)) {
            throw new InvalidParameterException(String.format("Missing value for config property: %s", key));
        }
        return value;
    }
}
