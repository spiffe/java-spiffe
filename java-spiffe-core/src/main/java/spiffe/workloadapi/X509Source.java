package spiffe.workloadapi;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.val;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.result.Error;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;
import spiffe.svid.x509svid.X509SvidSource;

import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;

/**
 * A <code>X509Source</code> represents a source of X509-SVID and X509 Bundles maintained via the
 * Workload API.
 * <p>
 * It handles an instance of a {@link X509Context} that is updated using a {@link WorkloadApiClient},
 * on this client it is registered a Watcher for consuming the updates from the Workload API.
 */
@Log
public class X509Source implements X509SvidSource, X509BundleSource {

    private X509Context x509Context;
    private WorkloadApiClient workloadApiClient;

    /**
     * Creates a new X509Source. It blocks until the initial update
     * has been received from the Workload API.
     * <p>
     * When it gets the response, it updates the x509Context instance.
     * <p>
     * Then registers a Watcher on the @param x509ContextFetcher to watch and act on
     * the x509Context updates.
     *
     * @param spiffeSocketPath a Path to a Spiffe Socket Endpoint.
     * @throws RuntimeException in case of failing the first X509Context fetch.
     */
    public static Result<X509Source, Throwable> newSource(@NonNull Path spiffeSocketPath) {
        Result<WorkloadApiClient, Throwable> workloadApiClient = WorkloadApiClient.newClient(spiffeSocketPath);
        if (workloadApiClient.isError()) {
            return Result.error(workloadApiClient.getError());
        }
        return newSource(workloadApiClient.getValue());
    }

    public static Result<X509Source, Throwable> newSource(@NonNull WorkloadApiClient workloadApiClient) {
        val x509Source = new X509Source(workloadApiClient);

        try {
            val initResult = x509Source.init();
            if (initResult.isError()) {
                return Result.error(initResult.getError());
            }
        } catch (RuntimeException e) {
            return Result.error(e);
        }

        return Result.ok(x509Source);
    }

    @SneakyThrows
    private Result<Boolean, Throwable> init() {
        CountDownLatch countDownLatch = new CountDownLatch(1);
        setX509ContextWatcher(countDownLatch);
        countDownLatch.await();
        return Result.ok(true);
    }

    private void setX509ContextWatcher(CountDownLatch countDownLatch) {
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void OnUpdate(X509Context update) {
                log.log(Level.INFO, "Received X509Context update");
                handleX509ContextUpdate(update);
                countDownLatch.countDown();
            }

            @Override
            public void OnError(Error<X509Context, Throwable> error) {
                throw new RuntimeException(error.getError());
            }
        });
    }

    private X509Source(@NonNull WorkloadApiClient workloadApiClient) {
        this.workloadApiClient= workloadApiClient;
    }

    private void handleX509ContextUpdate(@NonNull final X509Context update) {
        this.x509Context = update;
    }

    @Override
    public X509Svid getX509Svid() {
        return x509Context.getX509Svid();
    }

    @Override
    public Optional<X509Bundle> getX509BundleForTrustDomain(@NonNull final TrustDomain trustDomain) {
        return x509Context
                .getX509BundleSet()
                .getX509BundleForTrustDomain(trustDomain);
    }
}
