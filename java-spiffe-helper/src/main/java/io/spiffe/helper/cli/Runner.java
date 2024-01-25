package io.spiffe.helper.cli;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper;
import lombok.extern.java.Log;
import lombok.val;

import java.nio.file.Paths;
import java.security.InvalidParameterException;
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
            log.severe(e.getMessage());
            System.exit(1);
        }
    }

    static void runApplication(final String... args) throws RunnerException {
        try {
            val configFilePath = Config.getCliConfigOption(args);
            val properties = Config.parseConfigFileProperties(Paths.get(configFilePath));
            val options = Config.createKeyStoreOptions(properties);
            try (val keyStoreHelper = KeyStoreHelper.create(options)) {
                keyStoreHelper.run(true);
            }
        } catch (SocketEndpointAddressException | KeyStoreHelperException | InvalidParameterException | KeyStoreException e) {
            throw new RunnerException(e);
        }
    }
}
