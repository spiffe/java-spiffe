package io.spiffe.helper.keystore;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.Address;
import io.spiffe.workloadapi.WorkloadApiClient;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class KeyStoreHelperTest {

    private WorkloadApiClient workloadApiClient;
    private WorkloadApiClient workloadApiClientErrorStub;
    private Path keyStoreFilePath;
    private Path trustStoreFilePath;

    @BeforeEach
    void setUp() {
        workloadApiClient = new WorkloadApiClientStub();
        workloadApiClientErrorStub = new WorkloadApiClientErrorStub();
    }

    @AfterEach
    void tearDown() {
        deleteFile(keyStoreFilePath);
        deleteFile(trustStoreFilePath);
    }

    @Test
    void testNewHelper_certs_are_stored_successfully() throws SocketEndpointAddressException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        String trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        String alias = "other_alias";
        KeyStoreType keyStoreType = KeyStoreType.JKS;

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStoreType(keyStoreType)
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias)
                .workloadApiClient(workloadApiClient)
                .build();

        // run KeyStoreHelper
        try (KeyStoreHelper keystoreHelper = KeyStoreHelper.create(options)) {
            keystoreHelper.run(false);
        } catch (KeyStoreHelperException e) {
            fail(e);
        }

        checkPrivateKeyEntry(keyStoreFilePath, keyStorePass, keyPass, keyStoreType, alias);
        String authority1Alias = "example.org.0";
        checkBundleEntries(trustStoreFilePath, trustStorePass, keyStoreType, authority1Alias);
    }

    @Test
    void testNewHelper_use_default_type_and_alias() throws KeyStoreException, SocketEndpointAddressException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException {

        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        String trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .workloadApiClient(workloadApiClient)
                .build();

        try (KeyStoreHelper keystoreHelper = KeyStoreHelper.create(options)) {
            keystoreHelper.run(false);
        } catch (KeyStoreHelperException e) {
            fail();
        }

        checkPrivateKeyEntry(keyStoreFilePath, keyStorePass, keyPass, KeyStoreType.getDefaultType(), KeyStoreHelper.DEFAULT_ALIAS);
        String authority1Alias = "example.org.0";
        checkBundleEntries(trustStoreFilePath, trustStorePass, KeyStoreType.getDefaultType(), authority1Alias);
    }

    @Test
    void testCreateHelper_keyStore_trustStore_same_file_throwsException() throws SocketEndpointAddressException {

        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        String alias = "other_alias";

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(keyStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias)
                .workloadApiClient(workloadApiClient)
                .build();

        try {
            KeyStoreHelper.create(options);
            fail("expected exception: KeyStore and TrustStore should use different files");
        } catch (KeyStoreHelperException e) {
            assertEquals("KeyStore and TrustStore should use different files", e.getMessage());
        } catch (KeyStoreException e) {
            fail(e);
        }
    }

    @Test
    void testCreateHelper_keyStore_cannotStoreCerts() throws SocketEndpointAddressException {

        keyStoreFilePath = Paths.get("dummy://invalid");
        trustStoreFilePath = Paths.get("dummy://otherinvalid");

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        String alias = "other_alias";

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias)
                .workloadApiClient(workloadApiClient)
                .build();

        try {
            KeyStoreHelper helper = KeyStoreHelper.create(options);
            helper.run(false);
            fail();
        } catch (KeyStoreHelperException e) {
            assertEquals("Error running KeyStoreHelper", e.getMessage());
            assertEquals("java.nio.file.NoSuchFileException: dummy:/invalid", e.getCause().getCause().getMessage());
        } catch (KeyStoreException e) {
            fail(e);
        }
    }

    @Test
    void testCreateKeyStoreHelper_createNewClient() throws Exception {
        new EnvironmentVariables(Address.SOCKET_ENV_VARIABLE, "unix:/tmp/test").execute(() -> {
            KeyStoreHelper.KeyStoreOptions options = getKeyStoreValidOptions(null);
            try {
                KeyStoreHelper.create(options);
            } catch (KeyStoreHelperException e) {
                fail();
            }
        });
    }

    @Test
    void testCreateKeyStoreHelper_nullParameter() {
        try {
            KeyStoreHelper.create(null);
        } catch (NullPointerException e) {
            assertEquals("options must not be null", e.getMessage());
        } catch (SocketEndpointAddressException | KeyStoreHelperException | KeyStoreException e) {
            fail();
        }
    }

    @Test
    void testCreateKeyStoreHelper_cannotRunIfClosed() throws Exception {
        KeyStoreHelper.KeyStoreOptions options = getKeyStoreValidOptions(workloadApiClient);
        try {
            KeyStoreHelper helper = KeyStoreHelper.create(options);
            helper.close();
            helper.run(true);
        } catch (IllegalStateException e) {
            assertEquals("KeyStoreHelper is closed", e.getMessage());
        } catch (KeyStoreHelperException e) {
            fail();
        }
    }

    @Test
    void testCreateKeyStoreHelper_throwsExceptionWhenNoUpdateCanBeFetched() throws Exception {
        KeyStoreHelper.KeyStoreOptions options = getKeyStoreValidOptions(workloadApiClientErrorStub);
        try {
            KeyStoreHelper helper = KeyStoreHelper.create(options);
            helper.run(false);
            fail();
        } catch (KeyStoreHelperException e) {
            assertEquals("Error running KeyStoreHelper", e.getMessage());
        }
    }

    @Test
    void keyStoreHelperOptions_allNull() {
        try {
            KeyStoreHelper.KeyStoreOptions.builder().build();
        } catch (NullPointerException e) {
            assertEquals("keyStorePath must not be null", e.getMessage());
        }
    }

    @Test
    void keyStoreHelperOptions_trustStorePathNull() {
        try {
            KeyStoreHelper.KeyStoreOptions
                    .builder()
                    .keyStorePath(Paths.get("test"))
                    .build();
        } catch (NullPointerException e) {
            assertEquals("trustStorePath must not be null", e.getMessage());
        }
    }

    @Test
    void keyStoreHelperOptions_keyStorePassNull() {
        try {
            KeyStoreHelper.KeyStoreOptions
                    .builder()
                    .keyStorePath(Paths.get("test"))
                    .trustStorePath(Paths.get("example"))
                    .build();
        } catch (NullPointerException e) {
            assertEquals("keyStorePass must not be null", e.getMessage());
        }
    }

    @Test
    void keyStoreHelperOptions_trustStorePassNull() {
        try {
            KeyStoreHelper.KeyStoreOptions
                    .builder()
                    .keyStorePath(Paths.get("test"))
                    .trustStorePath(Paths.get("example"))
                    .keyStorePass("example1")
                    .build();
        } catch (NullPointerException e) {
            assertEquals("trustStorePass must not be null", e.getMessage());
        }
    }

    @Test
    void keyStoreHelperOptions_keyPassNull() {
        try {
            KeyStoreHelper.KeyStoreOptions
                    .builder()
                    .keyStorePath(Paths.get("test"))
                    .trustStorePath(Paths.get("example"))
                    .keyStorePass("example1")
                    .trustStorePass("example2")
                    .build();
        } catch (NullPointerException e) {
            assertEquals("keyPass must not be null", e.getMessage());
        }
    }


    private KeyStoreHelper.KeyStoreOptions getKeyStoreValidOptions(WorkloadApiClient workloadApiClient) {
        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);
        String trustStorefileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStorefileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        String alias = "other_alias";

        KeyStoreHelper.KeyStoreOptions.Builder options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .keyAlias(alias);

        if (workloadApiClient != null) {
            options.workloadApiClient(workloadApiClient);
        }

        return options.build();
    }


    private void checkPrivateKeyEntry(Path keyStoreFilePath,
                                      String keyStorePassword,
                                      String privateKeyPassword,
                                      KeyStoreType keyStoreType,
                                      String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

        keyStore.load(Files.newInputStream(keyStoreFilePath), keyStorePassword.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        SpiffeId spiffeId = CertificateUtils.getSpiffeId((X509Certificate) chain[0]);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());

        assertEquals(1, chain.length);
        assertEquals("spiffe://example.org/workload-server", spiffeId.toString());
        assertNotNull(privateKey);
    }

    private void checkBundleEntries(Path keyStoreFilePath,
                                    String keyStorePassword,
                                    KeyStoreType keyStoreType,
                                    String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType.value());
        keyStore.load(Files.newInputStream(keyStoreFilePath), keyStorePassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate);

        SpiffeId spiffeId = CertificateUtils.getSpiffeId((X509Certificate) certificate);
        assertEquals(SpiffeId.parse("spiffe://example.org"), spiffeId);
    }

    private void deleteFile(Path file) {
        try {
            Files.delete(file);
        } catch (Exception e) {
            //ignore
        }
    }
}