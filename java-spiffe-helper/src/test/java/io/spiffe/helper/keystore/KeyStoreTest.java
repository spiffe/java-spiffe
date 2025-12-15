package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


public class KeyStoreTest {

    static final String ENTRY_ALIAS = "spiffe";

    private X509Svid x509Svid;

    private X509Bundle x509Bundle;
    private Path keyStoreFilePath;

    @BeforeEach
    void setup() throws X509SvidException, URISyntaxException, X509BundleException {
        x509Svid = X509Svid.load(
                Paths.get(toUri("testdata/svid.pem")),
                Paths.get(toUri("testdata/svid.key")));

        x509Bundle = X509Bundle.load(
                TrustDomain.parse("spiffe://example.org"),
                Paths.get(toUri("testdata/bundle.pem")));
    }

    @Test
    void testStore_PrivateKey_and_Cert_in_PKCS12_KeyStore() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String fileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(fileName);

        KeyStoreType keyStoreType = KeyStoreType.getDefaultType();
        String keyStorePassword = RandomStringUtils.randomAscii(12);
        String privateKeyPassword = RandomStringUtils.randomAlphanumeric(12);

        KeyStore keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        PrivateKeyEntry privateKeyEntry = PrivateKeyEntry.builder()
                .alias(ENTRY_ALIAS)
                .privateKey(x509Svid.getPrivateKey())
                .certificateChain(x509Svid.getChainArray())
                .password(privateKeyPassword)
                .build();

        keyStore.storePrivateKeyEntry(privateKeyEntry);

        checkPrivateKeyEntry(keyStoreFilePath, keyStorePassword, privateKeyPassword, keyStoreType, ENTRY_ALIAS);
    }

    @Test
    void testStoreBundle_in_JKS_KeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        String fileName = RandomStringUtils.randomAlphabetic(10);
        KeyStoreType keyStoreType = KeyStoreType.JKS;
        String keyStorePassword = RandomStringUtils.randomAlphanumeric(12);
        keyStoreFilePath = Paths.get(fileName);

        KeyStore keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        String authority1Alias = x509Bundle.getTrustDomain().getName() + ".1";
        String authority2Alias = x509Bundle.getTrustDomain().getName() + ".2";
        AuthorityEntry entry1 = AuthorityEntry.builder()
                .alias(authority1Alias)
                .certificate(x509Bundle.getX509Authorities().iterator().next())
                .build();

        AuthorityEntry entry2 = AuthorityEntry.builder()
                .alias(authority2Alias)
                .certificate(x509Bundle.getX509Authorities().iterator().next())
                .build();

        keyStore.storeAuthorityEntry(entry1);
        keyStore.storeAuthorityEntry(entry2);

        checkBundleEntries(keyStoreFilePath, keyStorePassword, keyStoreType, authority1Alias);
        checkBundleEntries(keyStoreFilePath, keyStorePassword, keyStoreType, authority2Alias);
    }

    @Test
    void testNewKeyStore_from_existing_file() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String fileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(fileName);

        KeyStoreType keyStoreType = KeyStoreType.getDefaultType();
        String keyStorePassword = RandomStringUtils.randomAscii(12);
        String privateKeyPassword = RandomStringUtils.randomAlphanumeric(12);

        KeyStore keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        PrivateKeyEntry privateKeyEntry = PrivateKeyEntry.builder()
                .alias(ENTRY_ALIAS)
                .privateKey(x509Svid.getPrivateKey())
                .certificateChain(x509Svid.getChainArray())
                .password(privateKeyPassword)
                .build();

        keyStore.storePrivateKeyEntry(privateKeyEntry);

        // create a new KeyStore using the same file
        KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();
    }

    @Test
    void testNewKeyStore_nullKeyStorePath_throwsException() throws KeyStoreException {
        try {
            KeyStore.builder().build();
            fail("exception expected");
        } catch (NullPointerException e) {
            assertEquals("keyStoreFilePath must not be null", e.getMessage());
        }
    }

    @Test
    void testNewKeyStore_nullKeyStoreType_throwsException() throws KeyStoreException {
        try {
            KeyStore.builder()
                    .keyStoreFilePath(Paths.get("anypath"))
                    .build();
            fail("exception expected");
        } catch (NullPointerException e) {
            assertEquals("keyStoreType must not be null", e.getMessage());
        }
    }

    @Test
    void testNewKeyStore_nullKeyStorePassword_throwsException() throws KeyStoreException {
        try {
            KeyStore.builder()
                    .keyStoreFilePath(Paths.get("anypath"))
                    .keyStoreType(KeyStoreType.PKCS12)
                    .build();
            fail("exception expected: keyStorePassword cannot be blank");
        } catch (NullPointerException e) {
            assertEquals("keyStorePassword must not be null", e.getMessage());
        }
    }

    @Test
    void testNewKeyStore_emptyKeyStorePassword_throwsException() throws KeyStoreException {
        try {
            KeyStore.builder()
                    .keyStoreFilePath(Paths.get("anypath"))
                    .keyStoreType(KeyStoreType.PKCS12)
                    .keyStorePassword("")
                    .build();
            fail("exception expected: keyStorePassword cannot be blank");
        } catch (IllegalArgumentException e) {
            assertEquals("keyStorePassword cannot be blank", e.getMessage());
        }
    }

    @Test
    void testLoadKeyStore_invalidFile() throws IOException {
        File file = new File("test.txt");
        file.createNewFile();
        try {
            KeyStore.builder()
                    .keyStoreFilePath(file.toPath())
                    .keyStoreType(KeyStoreType.PKCS12)
                    .keyStorePassword("example")
                    .build();
        } catch (KeyStoreException e) {
            assertEquals("KeyStore cannot be opened", e.getMessage());
        } finally {
            file.delete();
        }
    }

    @AfterEach
    void tearDown() {
        deleteFile(keyStoreFilePath);
    }

    private void checkPrivateKeyEntry(Path keyStoreFilePath,
                                      String keyStorePassword,
                                      String privateKeyPassword,
                                      KeyStoreType keyStoreType,
                                      String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

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

        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType.value());
        keyStore.load(Files.newInputStream(keyStoreFilePath), keyStorePassword.toCharArray());
        Certificate certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate);

        SpiffeId spiffeId = CertificateUtils.getSpiffeId((X509Certificate) certificate);
        assertEquals(SpiffeId.parse("spiffe://example.org"), spiffeId);
    }

    private void deleteFile(Path filePath) {
        try {
            Files.delete(filePath);
        } catch (Exception e) {
            // ignore
        }
    }
}
