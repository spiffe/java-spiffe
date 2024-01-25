package io.spiffe.helper.cli;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper;
import lombok.extern.java.Log;
import lombok.val;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.nio.file.Paths;
import java.security.KeyStoreException;

/**
 * Entry point of the java-spiffe-helper CLI application.
 */
@Log
public class Runner {

    private Runner() {
    }

    public static void main(final String... args) {
        try {
            runApplication(args);
        } catch (RunnerException e) {
            log.severe(ExceptionUtils.getStackTrace(e));
            System.exit(1);
        } catch (ParseException e) {
            log.severe(e.getMessage());
            System.exit(1);
        }
    }

    static void runApplication(final String... args) throws RunnerException, ParseException {
        try {
            val configFilePath = Config.getCliConfigOption(args);
            val properties = Config.parseConfigFileProperties(Paths.get(configFilePath));
            val options = Config.createKeyStoreOptions(properties);
            try (val keyStoreHelper = KeyStoreHelper.create(options)) {
                keyStoreHelper.run(true);
            }
        } catch (SocketEndpointAddressException | KeyStoreHelperException | KeyStoreException e) {
            throw new RunnerException(e);
        }
    }
}
