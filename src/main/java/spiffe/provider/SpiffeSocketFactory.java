package spiffe.provider;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.*;

/**
 * Custom implementation of SSLSocketFactory that provides methods to create Sockets
 * using the Spiffe KeyManager and TrustManager to provide and validate certificates
 * during the SSL Handshake
 *
 */
public class SpiffeSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory delegate = SpiffeContextFactory.getSSLContext().getSocketFactory();

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
        return delegate.createSocket(socket, s, i, b);
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException {
        return delegate.createSocket(s, i );
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException {
        return delegate.createSocket(s, i, inetAddress, i1);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return delegate.createSocket(inetAddress, i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return delegate.createSocket(inetAddress, i, inetAddress1, i1);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }
}
