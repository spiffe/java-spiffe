package io.spiffe.provider;

import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.CertificateUtils;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.svid.x509svid.X509SvidSource;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.net.ssl.X509KeyManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

public class SpiffeKeyManagerTest {

    @Mock
    X509SvidSource x509SvidSource;

    X509KeyManager keyManager;
    X509Svid x509Svid;

    @BeforeEach
    void setup() throws X509SvidException, URISyntaxException {
        MockitoAnnotations.initMocks(this);
        keyManager = (X509KeyManager) new SpiffeKeyManagerFactory().engineGetKeyManagers(x509SvidSource)[0];
        x509Svid = X509Svid
                .load(
                        Paths.get(toUri("testdata/cert.pem")),
                        Paths.get(toUri("testdata/key.pem")));
    }

    @Test
    void getCertificateChain_returnsAnArrayOfX509Certificates() throws CertificateException {
        when(x509SvidSource.getX509Svid()).thenReturn(x509Svid);

        val certificateChain = keyManager.getCertificateChain(DEFAULT_ALIAS);
        val spiffeId = CertificateUtils.getSpiffeId(certificateChain[0]);

        assertAll(
                () -> assertEquals(1, certificateChain.length),
                () -> assertEquals("spiffe://example.org/test", spiffeId.toString())
        );
    }

    @Test
    void getPrivateKey_aliasIsSpiffe_returnAPrivateKey() {
        when(x509SvidSource.getX509Svid()).thenReturn(x509Svid);

        val privateKey = keyManager.getPrivateKey(DEFAULT_ALIAS);

        assertNotNull(privateKey);
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}
