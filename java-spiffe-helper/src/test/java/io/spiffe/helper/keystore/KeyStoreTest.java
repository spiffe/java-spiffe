package io.spiffe.helper.keystore;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.X509BundleException;
import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.svid.x509svid.X509Svid;
import lombok.val;
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
        val fileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(fileName);

        val keyStoreType = KeyStoreType.getDefaultType();
        val keyStorePassword = RandomStringUtils.randomAscii(12);
        val privateKeyPassword = RandomStringUtils.randomAlphanumeric(12);

        val keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        val privateKeyEntry = PrivateKeyEntry.builder()
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
        val fileName = RandomStringUtils.randomAlphabetic(10);
        val keyStoreType = KeyStoreType.JKS;
        val keyStorePassword = RandomStringUtils.randomAlphanumeric(12);
        keyStoreFilePath = Paths.get(fileName);

        val keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        val authority1Alias = x509Bundle.getTrustDomain().getName() + ".1";
        val authority2Alias = x509Bundle.getTrustDomain().getName() + ".2";
        val entry1 = AuthorityEntry.builder()
                .alias(authority1Alias)
                .certificate(x509Bundle.getX509Authorities().iterator().next())
                .build();

        val entry2 = AuthorityEntry.builder()
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
        val fileName = RandomStringUtils.randomAlphabetic(10);
        keyStoreFilePath = Paths.get(fileName);

        val keyStoreType = KeyStoreType.getDefaultType();
        val keyStorePassword = RandomStringUtils.randomAscii(12);
        val privateKeyPassword = RandomStringUtils.randomAlphanumeric(12);

        val keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        val privateKeyEntry = PrivateKeyEntry.builder()
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
            assertEquals("keyStoreFilePath is marked non-null but is null", e.getMessage());
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
            assertEquals("keyStoreType is marked non-null but is null", e.getMessage());
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
            assertEquals("keyStorePassword is marked non-null but is null", e.getMessage());
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
            assertEquals("KeyStore cannot be created", e.getMessage());
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

        val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

        keyStore.load(Files.newInputStream(keyStoreFilePath), keyStorePassword.toCharArray());
        val chain = keyStore.getCertificateChain(alias);
        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) chain[0]);
        val privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());

        assertEquals(1, chain.length);
        assertEquals("spiffe://example.org/workload-server", spiffeId.toString());
        assertNotNull(privateKey);
    }

    private void checkBundleEntries(Path keyStoreFilePath,
                                    String keyStorePassword,
                                    KeyStoreType keyStoreType,
                                    String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());
        keyStore.load(Files.newInputStream(keyStoreFilePath), keyStorePassword.toCharArray());
        val certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate);

        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) certificate);
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
