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
 * Entry point of the CLI to run the KeyStoreHelper.
 */
@Log
public class Runner {

    private Runner() {
    }

    /**
     * Entry method of the CLI to run the {@link KeyStoreHelper}.
     * <p>
     * In the args needs to be passed the config file option as: "-c" and "path_to_config_file"
     *
     * @param args contains the option with the config file path
     * @throws RunnerException is there is an error configuring or creating the KeyStoreHelper.
     */
    public static void main(final String ...args) throws RunnerException {
        try {
            val configFilePath = Config.getCliConfigOption(args);
            val properties = Config.parseConfigFileProperties(Paths.get(configFilePath));
            val options = Config.createKeyStoreOptions(properties);
            try (val keyStoreHelper = KeyStoreHelper.create(options)) {
                keyStoreHelper.run(true);
            }
        } catch (SocketEndpointAddressException | KeyStoreHelperException | RunnerException | InvalidParameterException | KeyStoreException e) {
            log.severe(e.getMessage());
            throw new RunnerException(e);
        }
    }
}
