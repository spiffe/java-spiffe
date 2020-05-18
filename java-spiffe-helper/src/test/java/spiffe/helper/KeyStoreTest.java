package spiffe.helper;

import lombok.val;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import spiffe.exception.X509SvidException;
import spiffe.internal.CertificateUtils;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyStoreTest {

    static final String DEFAULT_ALIAS = "Spiffe";

    X509Svid x509Svid;
    private Path keyStoreFilePath;


    @BeforeEach
    void setup() throws X509SvidException, URISyntaxException {
        x509Svid = X509Svid
                .load(
                        Paths.get(toUri("testdata/x509cert.pem")),
                        Paths.get(toUri("testdata/pkcs8key.pem"))
                );
    }

    @Test
    void testStoreX509Svid_PrivateKey_and_Cert_in_PKCS12_KeyStore() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        keyStoreFilePath = Paths.get("keystore.p12");
        val keyStoreType = KeyStoreType.PKCS12;
        val keyStorePassword = "keystore-password".toCharArray();
        val privateKeyPassword = "privatekey-password".toCharArray();

        val keyStore = KeyStore.builder()
                .keyStoreFilePath(keyStoreFilePath)
                .keyStoreType(keyStoreType)
                .keyStorePassword(keyStorePassword)
                .build();

        val privateKeyEntry = PrivateKeyEntry.builder()
                .alias(DEFAULT_ALIAS)
                .privateKey(x509Svid.getPrivateKey())
                .certificateChain(x509Svid.getChainArray())
                .password(privateKeyPassword)
                .build();


        keyStore.storePrivateKey(privateKeyEntry);

        checkEntryWasStored(keyStoreFilePath, keyStorePassword, privateKeyPassword, keyStoreType, DEFAULT_ALIAS);
    }

    private void checkEntryWasStored(Path keyStoreFilePath,
                                     char[] keyStorePassword,
                                     char[] privateKeyPassword,
                                     KeyStoreType keyStoreType,
                                     String alias)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {

        val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

        keyStore.load(new FileInputStream(new File(keyStoreFilePath.toUri())), keyStorePassword);
        val  chain = keyStore.getCertificateChain(alias);
        val spiffeId = CertificateUtils.getSpiffeId((X509Certificate) chain[0]);
        val privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword);

        assertEquals(1, chain.length);
        assertEquals("spiffe://example.org/test", spiffeId.toString());
        assertNotNull(privateKey);
    }

    @AfterEach
    void tearDown() {
        try {
            Files.delete(keyStoreFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private URI toUri(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }
}
