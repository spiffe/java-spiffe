package io.spiffe.helper.cli;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Entry point of the java-spiffe-helper CLI application.
 */
public class Runner {

    private static final Logger log =
            Logger.getLogger(Runner.class.getName());

    private Runner() {
    }

    public static void main(final String... args) {
        try {
            runApplication(args);
        } catch (RunnerException e) {
            log.severe(ExceptionUtils.getStackTrace(e));
            System.exit(1);
        } catch (ParseException | IllegalArgumentException e) {
            log.severe(e.getMessage());
            System.exit(1);
        }
    }

    static void runApplication(final String... args) throws RunnerException, ParseException {
        try {
            String configFilePath = Config.getCliConfigOption(args);
            Properties properties = Config.parseConfigFileProperties(Paths.get(configFilePath));
            KeyStoreHelper.KeyStoreOptions options = Config.createKeyStoreOptions(properties);
            try (KeyStoreHelper keyStoreHelper = KeyStoreHelper.create(options)) {
                keyStoreHelper.run(true);
            }
        } catch (SocketEndpointAddressException | KeyStoreHelperException | KeyStoreException e) {
            throw new RunnerException(e);
        }
    }
}
