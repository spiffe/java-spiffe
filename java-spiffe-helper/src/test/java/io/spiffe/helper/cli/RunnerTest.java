package io.spiffe.helper.cli;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.RunnerException;
import org.junit.jupiter.api.Test;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.util.Properties;

import static io.spiffe.helper.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class RunnerTest {

    @Test
    void test_Main_KeyStorePathIsMissing() throws KeyStoreException, SocketEndpointAddressException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keystorepath.conf"));
        try {
            Runner.main("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (RunnerException e) {
            assertEquals("keyStorePath config is missing", e.getCause().getMessage());
        }
    }

    @Test
    void test_Main_KeyStorePassIsMissing() throws KeyStoreException, SocketEndpointAddressException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keystorepass.conf"));
        try {
            Runner.main("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (RunnerException e) {
            assertEquals("keyStorePass config is missing", e.getCause().getMessage());
        }
    }

    @Test
    void test_Main_KeyPassIsMissing() throws KeyStoreException, SocketEndpointAddressException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keypass.conf"));
        try {
            Runner.main("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (RunnerException e) {
            assertEquals("keyPass config is missing", e.getCause().getMessage());
        }
    }

    @Test
    void test_Main_TrustStorePathIsMissing() throws KeyStoreException, SocketEndpointAddressException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/cli/missing-truststorepath.conf"));
        try {
            Runner.main("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (RunnerException e) {
            assertEquals("trustStorePath config is missing", e.getCause().getMessage());
        }
    }

    @Test
    void test_Main_TrustStorePassIsMissing() throws KeyStoreException, SocketEndpointAddressException, URISyntaxException {
        final Path path = Paths.get(toUri("testdata/cli/missing-truststorepass.conf"));
        try {
            Runner.main("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (RunnerException e) {
            assertEquals("trustStorePass config is missing", e.getCause().getMessage());
        }
    }

    @Test
    void testGetCliConfigOption_abbreviated() {
        String option = null;
        try {
            option = Runner.getCliConfigOption("-c", "example");
        } catch (RunnerException e) {
            fail(e);
        }
        assertEquals("example", option);
    }

    @Test
    void testGetCliConfigOption() {
        String option = null;
        try {
            option = Runner.getCliConfigOption("--config", "example");
        } catch (RunnerException e) {
            fail(e);
        }
        assertEquals("example", option);
    }

    @Test
    void testGetCliConfigOption_nonExistent() {
        try {
            Runner.getCliConfigOption("--unknown", "example");
            fail("expected parse exception");
        } catch (RunnerException e) {
            assertEquals("Unrecognized option: --unknown. Use -c, --config <arg>", e.getMessage());
        }
    }

    @Test
    void test_ParseConfigFile() throws URISyntaxException, RunnerException {
        final Path path = Paths.get(toUri("testdata/cli/correct.conf"));
        final Properties properties = Runner.parseConfigFile(path);

        assertEquals("keystore123.p12", properties.getProperty("keyStorePath"));
        assertEquals("example123", properties.getProperty("keyStorePass"));
        assertEquals("pass123", properties.getProperty("keyPass"));
        assertEquals("truststore123.p12", properties.getProperty("trustStorePath"));
        assertEquals("otherpass123", properties.getProperty("trustStorePass"));
        assertEquals("jks", properties.getProperty("keyStoreType"));
        assertEquals("other_alias", properties.getProperty("keyAlias"));
        assertEquals("unix:/tmp/agent.sock", properties.getProperty("spiffeSocketPath"));
    }
}