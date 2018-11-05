package spiffe.provider;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class to create a custom SSLContext object initialized
 * with the Spiffe KeyManager and TrustManager
 *
 */
public class SpiffeContextFactory {

    private static String SSL_PROTOCOL = "TLSv1.2";

    static SSLContext getSSLContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
            sslContext.init(
                    new SpiffeKeyManagerFactory().engineGetKeyManagers(),
                    new SpiffeTrustManagerFactory().engineGetTrustManagers(),
                    null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }
}
