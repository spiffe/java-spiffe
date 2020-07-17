package io.spiffe.helper.cli;

import io.spiffe.helper.exception.RunnerException;
import io.spiffe.helper.keystore.KeyStoreHelper;
import io.spiffe.helper.keystore.KeyStoreType;
import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.Properties;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class ConfigTest {

    @Test
    void parseConfigFileProperties() throws URISyntaxException {
        val path = Paths.get(toUri("testdata/cli/correct.conf"));

        Properties properties = null;
        try {
            properties = Config.parseConfigFileProperties(path);
        } catch (RunnerException e) {
            fail(e);
        }

        assertEquals("keystore123.p12", properties.getProperty("keyStorePath"));
        assertEquals("example123", properties.getProperty("keyStorePass"));
        assertEquals("pass123", properties.getProperty("keyPass"));
        assertEquals("truststore123.p12", properties.getProperty("trustStorePath"));
        assertEquals("otherpass123", properties.getProperty("trustStorePass"));
        assertEquals("jks", properties.getProperty("keyStoreType"));
        assertEquals("other_alias", properties.getProperty("keyAlias"));
        assertEquals("unix:/tmp/test", properties.getProperty("spiffeSocketPath"));
    }

    @Test
    void parseConfigFile_doesNotExist() {
        val randomFileName = RandomStringUtils.randomAlphabetic(10);
        val path = Paths.get(randomFileName);
        try {
            Config.parseConfigFileProperties(path);
            fail();
        } catch (RunnerException e) {
            assertEquals("Cannot open config file: " + randomFileName, e.getMessage());
        }

    }

    @Test
    void getCliConfigOption_validOption() {
        try {
            String option = Config.getCliConfigOption("-c", "test");
            assertEquals("test", option);
        } catch (RunnerException e) {
            fail();
        }
    }

    @Test
    void getCliConfigOption_validLongOption() {
        try {
            String option = Config.getCliConfigOption("--config", "example");
            assertEquals("example", option);
        } catch (RunnerException e) {
            fail();
        }
    }

    @Test
    void getCliConfigOption_unknownOption() {
        try {
            String option = Config.getCliConfigOption("-a", "test");
        } catch (RunnerException e) {
            assertEquals("Unrecognized option: -a. Use -c, --config <arg>", e.getMessage());
        }
    }

    @Test
    void testGetCliConfigOption_unknownLongOption() {
        try {
            Config.getCliConfigOption("--unknown", "example");
            fail("expected parse exception");
        } catch (RunnerException e) {
            assertEquals("Unrecognized option: --unknown. Use -c, --config <arg>", e.getMessage());
        }
    }

    @Test
    void createKeyStoreOptions() throws URISyntaxException {
        Properties configuration = getValidConfiguration();
        KeyStoreHelper.KeyStoreOptions keyStoreOptions = Config.createKeyStoreOptions(configuration);

        assertEquals("keystore123.p12", keyStoreOptions.getKeyStorePath().toString());
        assertEquals("example123", keyStoreOptions.getKeyStorePass());
        assertEquals("pass123", keyStoreOptions.getKeyPass());
        assertEquals("truststore123.p12", keyStoreOptions.getTrustStorePath().toString());
        assertEquals("otherpass123", keyStoreOptions.getTrustStorePass());
        assertEquals("jks", keyStoreOptions.getKeyStoreType().value());
        assertEquals("other_alias", keyStoreOptions.getKeyAlias());
        assertEquals("unix:/tmp/test", keyStoreOptions.getSpiffeSocketPath());
    }

    @Test
    void createKeyStoreOptions_aRequiredProperty_is_missing() throws URISyntaxException {
        Properties configuration = getValidConfiguration();

        // remove a required config
        configuration.setProperty("trustStorePass", "");

        try {
            Config.createKeyStoreOptions(configuration);
            fail();
        } catch (Exception e) {
            assertEquals("Missing value for config property: trustStorePass", e.getMessage());
        }
    }

    @Test
    void createKeyStoreOptions_keyStoreTypeMissing_useDefault() throws URISyntaxException {
        Properties configuration = getValidConfiguration();

        configuration.setProperty("keyStoreType", "");

        KeyStoreHelper.KeyStoreOptions keyStoreOptions = Config.createKeyStoreOptions(configuration);
        assertEquals(KeyStoreType.getDefaultType(), keyStoreOptions.getKeyStoreType());
    }

    Properties getValidConfiguration() throws URISyntaxException {
        val path = Paths.get(toUri("testdata/cli/correct.conf"));
        Properties properties = null;
        try {
            return Config.parseConfigFileProperties(path);
        } catch (RunnerException e) {
            throw new IllegalStateException(e);
        }
    }
}