package io.spiffe.helper.cli;

import io.spiffe.helper.exception.RunnerException;
import lombok.val;
import org.apache.commons.cli.ParseException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class RunnerTest {

    @Test
    void test_Main_KeyStorePathIsMissing() throws URISyntaxException, RunnerException, ParseException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keystorepath.conf"));
        try {
            Runner.runApplication("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (IllegalArgumentException e) {
            assertEquals("Missing value for config property: keyStorePath", e.getMessage());
        }
    }

    @Test
    void test_Main_KeyStorePassIsMissing() throws URISyntaxException, RunnerException, ParseException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keystorepass.conf"));
        try {
            Runner.runApplication("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (IllegalArgumentException e) {
            assertEquals("Missing value for config property: keyStorePass", e.getMessage());
        }
    }

    @Test
    void test_Main_KeyPassIsMissing() throws URISyntaxException, RunnerException, ParseException {
        final Path path = Paths.get(toUri("testdata/cli/missing-keypass.conf"));
        try {
            Runner.runApplication("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (IllegalArgumentException e) {
            assertEquals("Missing value for config property: keyPass", e.getMessage());
        }
    }

    @Test
    void test_Main_TrustStorePathIsMissing() throws URISyntaxException, RunnerException, ParseException {
        final Path path = Paths.get(toUri("testdata/cli/missing-truststorepath.conf"));
        try {
            Runner.runApplication("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (IllegalArgumentException e) {
            assertEquals("Missing value for config property: trustStorePath", e.getMessage());
        }
    }

    @Test
    void test_Main_TrustStorePassIsMissing() throws URISyntaxException, RunnerException, ParseException {
        final Path path = Paths.get(toUri("testdata/cli/missing-truststorepass.conf"));
        try {
            Runner.runApplication("-c", path.toString());
            fail("expected exception: property is missing");
        } catch (IllegalArgumentException e) {
            assertEquals("Missing value for config property: trustStorePass", e.getMessage());
        }
    }

    @Test
    void test_Main_throwsExceptionIfTheKeystoreCannotBeCreated() throws URISyntaxException, IOException, ParseException {
        val file = new File("keystore123.p12");
        file.createNewFile();

        val configPath = Paths.get(toUri("testdata/cli/correct.conf"));
        try {
            Runner.runApplication("-c", configPath.toString());
        } catch (RunnerException e) {
            assertEquals("KeyStore cannot be opened", e.getCause().getMessage());
        } finally {
            file.delete();
        }
    }

}