package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.bundle.x509bundle.X509BundleSet;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.helper.exception.KeyStoreHelperException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.X509CertificateTestUtils;
import io.spiffe.workloadapi.Address;
import io.spiffe.workloadapi.Watcher;
import io.spiffe.workloadapi.WorkloadApiClient;
import io.spiffe.workloadapi.X509Context;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;

import java.io.InputStream;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    void testNewHelper_storesMultipleAuthoritiesForSameTrustDomain() throws Exception {
        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        String trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        KeyStoreType keyStoreType = KeyStoreType.JKS;

        Set<X509Certificate> authorities = new HashSet<>();
        authorities.add(X509CertificateTestUtils.createRootCA("CN=Root CA 1", "spiffe://example.org").getCertificate());
        authorities.add(X509CertificateTestUtils.createRootCA("CN=Root CA 2", "spiffe://example.org").getCertificate());

        WorkloadApiClient client = new WorkloadApiClientStub() {
            @Override
            public void watchX509Context(Watcher<X509Context> watcher) {
                X509Context context = fetchX509Context();
                X509Bundle bundle = new X509Bundle(TrustDomain.parse("example.org"), authorities);
                X509BundleSet bundleSet = X509BundleSet.of(Collections.singleton(bundle));
                watcher.onUpdate(X509Context.of(context.getX509Svids(), bundleSet));
            }
        };

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStoreType(keyStoreType)
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .workloadApiClient(client)
                .build();

        try (KeyStoreHelper keystoreHelper = KeyStoreHelper.create(options)) {
            keystoreHelper.run(false);
        } catch (KeyStoreHelperException e) {
            fail(e);
        }

        KeyStore trustStore = java.security.KeyStore.getInstance(keyStoreType.value());
        try (InputStream trustStoreInputStream = Files.newInputStream(trustStoreFilePath)) {
            trustStore.load(trustStoreInputStream, trustStorePass.toCharArray());
        }

        Certificate authority1 = trustStore.getCertificate("example.org.0");
        Certificate authority2 = trustStore.getCertificate("example.org.1");
        assertNotNull(authority1);
        assertNotNull(authority2);
        assertEquals(2, trustStore.size());
        Set<X509Certificate> storedAuthorities = new HashSet<>();
        storedAuthorities.add((X509Certificate) authority1);
        storedAuthorities.add((X509Certificate) authority2);
        assertEquals(authorities, storedAuthorities);
    }

    @Test
    void testNewHelper_removesStaleAuthoritiesForSameTrustDomain() throws Exception {
        String keyStorefileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(keyStorefileName);

        String trustStoreFileName = RandomStringUtils.randomAlphabetic(10);
        trustStoreFilePath = Paths.get(trustStoreFileName);

        String trustStorePass = "truststore123";
        String keyStorePass = "keystore123";
        String keyPass = "keypass123";
        KeyStoreType keyStoreType = KeyStoreType.JKS;

        X509Certificate authority1 = X509CertificateTestUtils.createRootCA("CN=Root CA 1", "spiffe://example.org").getCertificate();
        X509Certificate authority2 = X509CertificateTestUtils.createRootCA("CN=Root CA 2", "spiffe://example.org").getCertificate();

        Set<X509Certificate> initialAuthorities = new HashSet<>();
        initialAuthorities.add(authority1);
        initialAuthorities.add(authority2);

        Set<X509Certificate> rotatedAuthorities = new HashSet<>();
        rotatedAuthorities.add(authority1);

        WorkloadApiClient client = new WorkloadApiClientStub() {
            @Override
            public void watchX509Context(Watcher<X509Context> watcher) {
                X509Context context = fetchX509Context();
                X509Bundle initialBundle = new X509Bundle(TrustDomain.parse("example.org"), initialAuthorities);
                watcher.onUpdate(X509Context.of(
                        context.getX509Svids(),
                        X509BundleSet.of(Collections.singleton(initialBundle))
                ));

                X509Bundle rotatedBundle = new X509Bundle(TrustDomain.parse("example.org"), rotatedAuthorities);
                watcher.onUpdate(X509Context.of(
                        context.getX509Svids(),
                        X509BundleSet.of(Collections.singleton(rotatedBundle))
                ));
            }
        };

        final KeyStoreHelper.KeyStoreOptions options = KeyStoreHelper.KeyStoreOptions
                .builder()
                .keyStoreType(keyStoreType)
                .keyStorePath(keyStoreFilePath)
                .keyStorePass(keyStorePass)
                .trustStorePath(trustStoreFilePath)
                .trustStorePass(trustStorePass)
                .keyPass(keyPass)
                .workloadApiClient(client)
                .build();

        try (KeyStoreHelper keystoreHelper = KeyStoreHelper.create(options)) {
            keystoreHelper.run(false);
        } catch (KeyStoreHelperException e) {
            fail(e);
        }

        KeyStore trustStore = java.security.KeyStore.getInstance(keyStoreType.value());
        try (InputStream trustStoreInputStream = Files.newInputStream(trustStoreFilePath)) {
            trustStore.load(trustStoreInputStream, trustStorePass.toCharArray());
        }

        assertEquals(authority1, trustStore.getCertificate("example.org.0"));
        assertNull(trustStore.getCertificate("example.org.1"));
        assertEquals(1, trustStore.size());
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

        try (InputStream keyStoreInputStream = Files.newInputStream(keyStoreFilePath)) {
            keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());
        }
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
        try (InputStream keyStoreInputStream = Files.newInputStream(keyStoreFilePath)) {
            keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());
        }
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