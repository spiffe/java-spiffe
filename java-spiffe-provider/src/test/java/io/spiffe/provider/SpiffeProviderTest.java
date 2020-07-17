package io.spiffe.provider;

import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SpiffeProviderTest {

    @Test
    void install() throws NoSuchAlgorithmException {
        SpiffeProvider.install();
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(SpiffeProviderConstants.ALGORITHM);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(SpiffeProviderConstants.ALGORITHM);
        assertNotNull(keyManagerFactory);
        assertNotNull(trustManagerFactory);

        // should do nothing
        SpiffeProvider.install();
    }
}