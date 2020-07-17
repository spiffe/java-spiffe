package io.spiffe.provider;

import io.spiffe.exception.X509SvidException;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.svid.x509svid.X509SvidSource;
import io.spiffe.workloadapi.X509Source;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;
import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SpiffeKeyManagerFactoryTest {

    @Test
    void engineGetKeyManagers_usingX509SourceManager() throws NoSuchFieldException, IllegalAccessException {
        // init singleton with an instance
        Field field = X509SourceManager.class.getDeclaredField("x509Source");
        field.setAccessible(true);
        X509Source source = new X509SourceStub();
        field.set(null, source);

        KeyManager[] keyManagers = new SpiffeKeyManagerFactory().engineGetKeyManagers();
        SpiffeKeyManager keyManager = (SpiffeKeyManager) keyManagers[0];

        X509Certificate[] chain = keyManager.getCertificateChain(DEFAULT_ALIAS);
        X509Certificate certificate = chain[0];

        assertEquals(source.getX509Svid().getChain().get(0), certificate);
    }

    @Test
    void engineGetKeyManagers_passingAX509SvidSource() throws URISyntaxException, X509SvidException {
        Path cert = Paths.get(toUri("testdata/cert.pem"));
        Path key = Paths.get(toUri("testdata/key.pem"));
        X509Svid svid = X509Svid.load(cert, key);
        X509SvidSource x509SvidSource = () -> svid;

        KeyManager[] keyManagers = new SpiffeKeyManagerFactory().engineGetKeyManagers(x509SvidSource);
        SpiffeKeyManager keyManager = (SpiffeKeyManager) keyManagers[0];

        assertEquals(svid.getChainArray()[0], keyManager.getCertificateChain(DEFAULT_ALIAS)[0]);
    }

    @Test
    void engineGetKeyManagers_nullParameter() {
        try {
            new SpiffeKeyManagerFactory().engineGetKeyManagers(null);
        } catch (NullPointerException e) {
            assertEquals("x509SvidSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void engineInit() {
        new SpiffeKeyManagerFactory().engineInit(null);
        new SpiffeKeyManagerFactory().engineInit(null, null);

    }
}