package io.spiffe.provider.examples.mtls;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.provider.SpiffeKeyManager;
import io.spiffe.provider.SpiffeProviderException;
import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import io.spiffe.provider.SpiffeTrustManager;
import io.spiffe.provider.X509SourceManager;
import io.spiffe.workloadapi.X509Source;
import lombok.val;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * Example of a simple HTTPS Server backed by the Workload API to get the X.509 certificates
 * and trusted bundles.
 * <p>
 * The purpose of this class is to show the use of the {@link SpiffeSslContextFactory} to create
 * a {@link SSLContext} that uses X.509-SVID provided by a Workload API. The SSLContext uses the
 * {@link SpiffeKeyManager} and {@link SpiffeTrustManager} for
 * providing certificates and doing chain and SPIFFE ID validation.
 * To run this example, Spire should be running, SPIFFE_ENDPOINT_SOCKET env variable should be
 * defined, and a property ssl.spiffe.accept should be defined in the java.security having a
 * spiffe id from a client workload.
 */
public class HttpsServer {

    int port;

    public static void main(String[] args) {
        HttpsServer httpsServer = new HttpsServer(4000);
        try {
            httpsServer.run();
        } catch (IOException | KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error starting HttpsServer", e);
        }
    }

    HttpsServer(int port ) {
        this.port = port;
    }

    void run() throws IOException, KeyManagementException, NoSuchAlgorithmException {
        X509Source x509Source;
        try {
            x509Source = X509SourceManager.getX509Source();
        } catch (SocketEndpointAddressException | X509SourceException e) {
            throw new SpiffeProviderException("Error at getting the X509Source instance", e);
        }

        val sslContextOptions = SslContextOptions
                .builder()
                .x509Source(x509Source)
                .build();
        SSLContext sslContext = SpiffeSslContextFactory.getSslContext(sslContextOptions);

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        try (SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port)) {
            // Server will validate Client chain and SPIFFE ID
            sslServerSocket.setNeedClientAuth(true);

            SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
            new WorkloadThread(sslSocket, x509Source).start();
        }
    }
}


