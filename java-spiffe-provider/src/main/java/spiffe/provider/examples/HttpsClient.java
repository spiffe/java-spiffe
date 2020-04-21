package spiffe.provider.examples;

import spiffe.provider.SpiffeSslContextFactory;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Example of a simple HTTPS Client backed by the Workload API to get the X509 Certificates
 * and trusted cert bundles.
 * <p>
 * The purpose of this class is to show the use of the {@link SpiffeSslContextFactory} to create
 * a {@link SSLContext} that uses X509-SVID provided by a Workload API. The SSLContext uses the
 * {@link spiffe.provider.SpiffeKeyManager} and {@link spiffe.provider.SpiffeTrustManager} for
 * providing certificates and doing chain and SPIFFE ID validation.
 */
public class HttpsClient {

    String spiffeSocket;
    Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsListSupplier;
    int serverPort;

    public static void main(String[] args) throws IOException {
        String spiffeSocket = "unix:/tmp/agent.sock";
        HttpsClient httpsClient =
                new HttpsClient(4000, spiffeSocket, HttpsClient::listOfSpiffeIds);
        httpsClient.run();
    }

    HttpsClient(int serverPort, String spiffeSocket, Supplier<Result<List<SpiffeId>, String>> acceptedSpiffeIdsListSupplier) {
        this.serverPort = serverPort;
        this.spiffeSocket = spiffeSocket;
        this.acceptedSpiffeIdsListSupplier = acceptedSpiffeIdsListSupplier;
    }

    void run() throws IOException {
        SSLContext sslContext = SpiffeSslContextFactory
                .getSslContext(spiffeSocket, acceptedSpiffeIdsListSupplier);

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", serverPort);
        new WorkloadThread(sslSocket).start();
    }

    static Result<List<SpiffeId>, String> listOfSpiffeIds() {
        List<SpiffeId> acceptedSpiffeIds = new ArrayList<>();
        acceptedSpiffeIds.add(
                SpiffeId.parse("spiffe://example.org/workload-server").getValue());
        return Result.ok(acceptedSpiffeIds);
    }

}

