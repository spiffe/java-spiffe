package io.spiffe.provider;

import io.spiffe.internal.CertificateUtils;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.svid.x509svid.X509SvidSource;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;
import static io.spiffe.utils.X509CertificateTestUtils.createCertificate;
import static io.spiffe.utils.X509CertificateTestUtils.createRootCA;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

public class SpiffeKeyManagerTest {

    @Mock
    X509SvidSource x509SvidSource;

    SpiffeKeyManager spiffeKeyManager;
    X509Svid x509Svid;

    @BeforeEach
    void setup() throws Exception {
        MockitoAnnotations.initMocks(this);

        val rootCa = createRootCA("C = US, O = SPIFFE", "spiffe://domain.test");
        val leaf = createCertificate("C = US, O = SPIRE", "C = US, O = SPIRE", "spiffe://domain.test/workload", rootCa, false);

        X509Svid svid = X509Svid.parseRaw(leaf.getCertificate().getEncoded(), leaf.getKeyPair().getPrivate().getEncoded());

        x509Svid = X509Svid.load(
                Paths.get(toUri("testdata/cert.pem")),
                Paths.get(toUri("testdata/key.pem")));
        when(x509SvidSource.getX509Svid()).thenReturn(x509Svid);

        spiffeKeyManager = new SpiffeKeyManager(x509SvidSource);
    }

    @Test
    void testCreateNewSpiffeKeyManager_nullSource() {
        try {
            new SpiffeKeyManager(null);
            fail();
        } catch (Exception e) {
            assertEquals("x509SvidSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void getCertificateChain() throws CertificateException {
        val certificateChain = spiffeKeyManager.getCertificateChain(DEFAULT_ALIAS);
        val spiffeId = CertificateUtils.getSpiffeId(certificateChain[0]);

        assertAll(
                () -> assertEquals(1, certificateChain.length),
                () -> assertEquals("spiffe://example.org/test", spiffeId.toString())
        );
    }

    @Test
    void getCertificateChain_aliasNotSupported() {
        X509Certificate[] chain = spiffeKeyManager.getCertificateChain("other_alias");
        assertEquals(0, chain.length);
    }

    @Test
    void getPrivateKey_aliasIsSpiffe_returnAPrivateKey() {
        val privateKey = spiffeKeyManager.getPrivateKey(DEFAULT_ALIAS);
        assertNotNull(privateKey);
    }

    @Test
    void getPrivateKey_aliasNotSupported() {
        PrivateKey privateKey = spiffeKeyManager.getPrivateKey("other_alias");
        assertNull(privateKey);
    }

    @Test
    void getClientAliases() {
        String[] aliases = spiffeKeyManager.getClientAliases("EC", null);
        assertEquals(DEFAULT_ALIAS, aliases[0]);
    }

    @Test
    void chooseClientAlias() {
        String alias = spiffeKeyManager.chooseClientAlias(new String[]{"EC"}, null, null);
        assertEquals(DEFAULT_ALIAS, alias);
    }

    @Test
    void chooseEngineClientAlias() {
        String alias = spiffeKeyManager.chooseEngineClientAlias(new String[]{"EC"}, null, null);
        assertEquals(DEFAULT_ALIAS, alias);
    }

    @Test
    void getServerAliases() {
        String[] aliases = spiffeKeyManager.getServerAliases("EC", null);
        assertEquals(DEFAULT_ALIAS, aliases[0]);
    }

    @Test
    void chooseEngineServerAlias() {
        String alias = spiffeKeyManager.chooseEngineServerAlias("EC", null, null);
        assertEquals(DEFAULT_ALIAS, alias);
    }

    @Test
    void chooseServerAlias() {
        String alias = spiffeKeyManager.chooseServerAlias("EC", null, null);
        assertEquals(DEFAULT_ALIAS, alias);
    }

    @Test
    void chooseServerAlias_keyTypeNotSupported() {
        String alias = spiffeKeyManager.chooseServerAlias("not-supported", null, null);
        assertNull(alias);
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}
