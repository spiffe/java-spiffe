package spiffe.helper.cli;

import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.helper.keystore.KeyStoreHelper;
import spiffe.helper.keystore.KeyStoreType;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.util.Properties;

/**
 * Entry point of the CLI to run the KeyStoreHelper.
 */
@Log
public class Runner {

    public static void main(String[] args) {
        Properties parameters;
        String configFilePath = null;
        try {
            configFilePath = getCliConfigOption(args);
            parameters = parseConfigFile(configFilePath);
            KeyStoreHelper.KeyStoreOptions options = toKeyStoreOptions(parameters);
            new KeyStoreHelper(options);
        } catch (IOException e) {
            log.severe(String.format("Cannot open config file: %s %n %s", configFilePath, e.getMessage()));
        } catch (KeyStoreException e) {
            log.severe(String.format("Error storing certs in keystores: %s", e.getMessage()));
        } catch (SocketEndpointAddressException e) {
            log.severe(String.format("Workload API address is not valid: %s", e.getMessage()));
        } catch (ParseException e) {
            log.severe(String.format( "%s. Use -c, --config <arg>", e.getMessage()));
        }
    }

    static Properties parseConfigFile(String configFile) throws IOException {
        Properties prop = new Properties();
        try (InputStream in = new FileInputStream(configFile)){
            prop.load(in);
        }
        return prop;
    }

    static String getCliConfigOption(String[] args) throws ParseException {
        final Options cliOptions = new Options();
        final Option confOption = new Option("c", "config", true, "config file");
        confOption.setRequired(true);
        cliOptions.addOption(confOption);
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(cliOptions, args);
        return cmd.getOptionValue("config");
    }

    private static KeyStoreHelper.KeyStoreOptions toKeyStoreOptions(Properties properties) {

        val keyStorePath = getString(properties, "keyStorePath");
        if (StringUtils.isBlank(keyStorePath)) {
            throw new IllegalArgumentException("keyStorePath config is missing");
        }

        val keyStorePass = getString(properties, "keyStorePass");
        if (StringUtils.isBlank(keyStorePass)) {
            throw new IllegalArgumentException("keyStorePass config is missing");
        }

        val keyPass = getString(properties, "keyPass");
        if (StringUtils.isBlank(keyPass)) {
            throw new IllegalArgumentException("keyPass config is missing");
        }

        val trustStorePath = getString(properties, "trustStorePath");
        if (StringUtils.isBlank(trustStorePath)) {
            throw new IllegalArgumentException("trustStorePath config is missing");
        }

        val trustStorePass = getString(properties, "trustStorePass");
        if (StringUtils.isBlank(trustStorePass)) {
            throw new IllegalArgumentException("trustStorePass config is missing");
        }

        val keyAlias = getString(properties, "keyAlias");
        val spiffeSocketPath = getString(properties, "spiffeSocketPath");

        KeyStoreType keyStoreType = null;
        val keyStoreTypeProp = properties.get("keyStoreType");
        if (keyStoreTypeProp != null) {
            keyStoreType = KeyStoreType.parse(keyStoreTypeProp);
        }

        return KeyStoreHelper.KeyStoreOptions.builder()
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

    private static String getString(Properties properties, String propName) {
        final String property = properties.getProperty(propName);
        if (property == null) {
            return "";
        }
        return property;
    }
}
