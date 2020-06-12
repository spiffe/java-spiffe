package spiffe.provider.examples.mtls;

import lombok.val;
import spiffe.exception.SocketEndpointAddressException;
import spiffe.exception.X509SourceException;
import spiffe.provider.SpiffeSslContextFactory;
import spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.SpiffeIdUtils;
import spiffe.workloadapi.X509Source;
import spiffe.workloadapi.X509Source.X509SourceOptions;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.function.Supplier;

/**
 * Example of a simple HTTPS Client backed by the Workload API to get the X.509 Certificates
 * and trusted cert bundles.
 * <p>
 * The purpose of this class is to show the use of the {@link SpiffeSslContextFactory} to create
 * a {@link SSLContext} that uses X.509-SVID provided by a Workload API. The SSLContext uses the
 * {@link spiffe.provider.SpiffeKeyManager} and {@link spiffe.provider.SpiffeTrustManager} for
 * providing certificates and doing chain and SPIFFE ID validation.
 */
public class HttpsClient {

    String spiffeSocket;
    Supplier<List<SpiffeId>> acceptedSpiffeIdsListSupplier;
    int serverPort;

    public static void main(String[] args) {
        String spiffeSocket = "unix:/tmp/agent.sock";
        HttpsClient httpsClient = new HttpsClient(4000, spiffeSocket, () -> new AcceptedSpiffeIds().getList());
        try {
            httpsClient.run();
        } catch (KeyManagementException | NoSuchAlgorithmException | IOException | SocketEndpointAddressException | X509SourceException e) {
            throw new RuntimeException("Error starting Https Client", e);
        }
    }

    HttpsClient(int serverPort, String spiffeSocket, Supplier<List<SpiffeId>> acceptedSpiffeIdsListSupplier) {
        this.serverPort = serverPort;
        this.spiffeSocket = spiffeSocket;
        this.acceptedSpiffeIdsListSupplier = acceptedSpiffeIdsListSupplier;
    }

    void run() throws IOException, SocketEndpointAddressException, KeyManagementException, NoSuchAlgorithmException, X509SourceException {

        val sourceOptions = X509SourceOptions
                .builder()
                .spiffeSocketPath(spiffeSocket)
                .build();
        val x509Source = X509Source.newSource(sourceOptions);

        SslContextOptions sslContextOptions = SslContextOptions
                .builder()
                .acceptedSpiffeIdsSupplier(acceptedSpiffeIdsListSupplier)
                .x509Source(x509Source)
                .build();
        SSLContext sslContext = SpiffeSslContextFactory.getSslContext(sslContextOptions);

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", serverPort);

        new WorkloadThread(sslSocket, x509Source).start();
    }

    private static class AcceptedSpiffeIds {
        List<SpiffeId> getList() {
            try {
                return SpiffeIdUtils.getSpiffeIdListFromFile(Paths.get(toUri("testdata/spiffeIds.txt")));
            } catch (IOException | URISyntaxException e) {
                throw new RuntimeException("Error getting list of spiffeIds", e);
            }
        }


        URI toUri(String path) throws URISyntaxException {
            return getClass().getClassLoader().getResource(path).toURI();
        }
    }
}

