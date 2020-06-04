package spiffe.helper.keystore;

import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.exception.X509SvidException;
import spiffe.internal.CertificateUtils;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
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

import static org.junit.jupiter.api.Assertions.*;

public class KeyStoreTest {

    static final String ENTRY_ALIAS = "spiffe";

    private X509Svid x509Svid;

    private X509Bundle x509Bundle;
    private Path keyStoreFilePath;

    @BeforeEach
    void setup() throws X509SvidException, URISyntaxException, IOException, CertificateException {
        x509Svid = X509Svid.load(
                Paths.get(toUri("testdata/svid.pem")),
                Paths.get(toUri("testdata/svid.key")));

        x509Bundle = X509Bundle.load(
                TrustDomain.of("spiffe://example.org"),
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
            KeyStore.builder()
                    .keyStoreFilePath(null)
                    .keyStoreType(KeyStoreType.JKS)
                    .keyStorePassword("keyStorePassword")
                    .build();
            fail("exception expected");
        } catch (NullPointerException e) {
            assertEquals("keyStoreFilePath is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testNewKeyStore_nullKeyStorePassword_throwsException() throws KeyStoreException {
        try {
            KeyStore.builder()
                    .keyStoreFilePath(Paths.get("anypath"))
                    .keyStoreType(KeyStoreType.PKCS12)
                    .keyStorePassword(null)
                    .build();
            fail("exception expected");
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

        keyStore.load(new FileInputStream(new File(keyStoreFilePath.toUri())), keyStorePassword.toCharArray());
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
        keyStore.load(new FileInputStream(new File(keyStoreFilePath.toUri())), keyStorePassword.toCharArray());
        val certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate);

        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) certificate);
        assertEquals(SpiffeId.parse("spiffe://example.org"), spiffeId);
    }

    private URI toUri(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }

    private void deleteFile(Path filePath) {
        try {
            Files.delete(filePath);
        } catch (Exception e) {
            // ignore
        }
    }
}
