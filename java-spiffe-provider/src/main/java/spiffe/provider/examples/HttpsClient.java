package spiffe.provider.examples;

import lombok.val;
import spiffe.provider.SpiffeSslContextFactory;
import spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.workloadapi.X509Source;
import spiffe.workloadapi.X509Source.X509SourceOptions;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

        val sourceOptions = X509SourceOptions
                .builder()
                .spiffeSocketPath(spiffeSocket)
                .build();
        val x509Source = X509Source.newSource(sourceOptions);
        if (x509Source.isError()) {
            throw new RuntimeException(x509Source.getError());
        }

        SslContextOptions sslContextOptions = SslContextOptions
                .builder()
                .acceptedSpiffeIdsSupplier(acceptedSpiffeIdsListSupplier)
                .x509Source(x509Source.getValue())
                .build();
        Result<SSLContext, String> sslContext = SpiffeSslContextFactory
                .getSslContext(sslContextOptions);

        if (sslContext.isError()) {
            throw new RuntimeException(sslContext.getError());
        }

        SSLSocketFactory sslSocketFactory = sslContext.getValue().getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", serverPort);

        new WorkloadThread(sslSocket, x509Source.getValue()).start();
    }

    static Result<List<SpiffeId>, String> listOfSpiffeIds() {
        try {
            Path path = Paths.get("java-spiffe-provider/src/main/java/spiffe/provider/examples/spiffeIds.txt");
            Stream<String> lines = Files.lines(path);
            List<SpiffeId> list = lines
                    .map(SpiffeId::parse)
                    .map(Result::getValue)
                    .collect(Collectors.toList());
            return Result.ok(list);
        } catch (Exception e) {
           return Result.error("Error getting list of accepted SPIFFE IDs: %s", e.getMessage());
        }
    }
}

