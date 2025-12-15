package io.spiffe.provider;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.SpiffeIdUtils;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.spiffe.provider.SpiffeProviderConstants.SSL_SPIFFE_ACCEPT_PROPERTY;

/**
 * Implementation of {@link SSLSocketFactory} that provides methods to create {@link javax.net.ssl.SSLSocket}
 * backed by a SPIFFE SSLContext {@link SpiffeSslContextFactory}.
 */
public class SpiffeSslSocketFactory extends SSLSocketFactory {

    private static final Logger log =
            Logger.getLogger(SpiffeSslSocketFactory.class.getName());

    private final SSLSocketFactory delegate;

    /**
     * Default Constructor.
     *
     * This SpiffeSslSocketFactory is backed by SPIFFE-aware SSLContext that obtains certificates
     * from the SPIFFE Workload API, connecting to a socket configured through the environment variable
     * 'SPIFFE_ENDPOINT_SOCKET'.
     *
     * The list of accepted SPIFFE IDs, that will be used to validate the SAN in a peer certificate,
     * can be configured through the property 'ssl.spiffe.accept', separating the SPIFFE IDs using commas
     * without spaces, e.g., '-Dssl.spiffe.accept=spiffe://domain.test/service,spiffe://example.org/app'
     * If the property is not set, any SPIFFE ID will be accepted in a TLS connection.
     *
     * @throws NoSuchAlgorithmException if there is a problem creating the SSL context
     * @throws KeyManagementException   if there is a problem initializing the SSL context
     * @throws X509SourceException if there is a problem creating the source of X.509 certificates
     * @throws SocketEndpointAddressException if there is a problem connecting to the local SPIFFE socket
     *
     */
    public SpiffeSslSocketFactory() throws SocketEndpointAddressException, X509SourceException, NoSuchAlgorithmException, KeyManagementException {
        log.log(Level.INFO, "Creating SpiffeSslSocketFactory");

        SSLContext sslContext;
        Supplier<Set<SpiffeId>> acceptedSpiffeIds;
        SslContextOptions options;

        X509Source x509source = DefaultX509Source.newSource();
        String envProperty = EnvironmentUtils.getProperty(SSL_SPIFFE_ACCEPT_PROPERTY);

        if (StringUtils.isNotBlank(envProperty)) {
            acceptedSpiffeIds = () -> SpiffeIdUtils.toSetOfSpiffeIds(envProperty, ',');
            options = SslContextOptions.builder().acceptedSpiffeIdsSupplier(acceptedSpiffeIds).x509Source(x509source).build();
        } else {
            options = SslContextOptions.builder().acceptAnySpiffeId().x509Source(x509source).build();
        }

        sslContext = SpiffeSslContextFactory.getSslContext(options);
        delegate = sslContext.getSocketFactory();
    }

    /**
     * Constructor.
     *
     * @param contextOptions options for creating the SSL Context
     * @throws NoSuchAlgorithmException if there is a problem creating the SSL context
     * @throws KeyManagementException if there is a problem initializing the SSL context
     */
    public SpiffeSslSocketFactory(final SslContextOptions contextOptions)
            throws KeyManagementException, NoSuchAlgorithmException {
        final SSLContext sslContext = SpiffeSslContextFactory.getSslContext(contextOptions);
        delegate = sslContext.getSocketFactory();
    }

    SpiffeSslSocketFactory(final SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

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
        return delegate.createSocket(s, i);
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
