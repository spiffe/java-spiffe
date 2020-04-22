package spiffe.workloadapi;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.java.Log;
import lombok.val;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSet;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.result.Error;
import spiffe.result.Result;
import spiffe.spiffeid.TrustDomain;
import spiffe.svid.x509svid.X509Svid;
import spiffe.svid.x509svid.X509SvidSource;

import java.io.Closeable;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Level;

/**
 * A <code>X509Source</code> represents a source of X509-SVID and X509 Bundles maintained via the
 * Workload API.
 * <p>
 * It handles a {@link X509Svid} and a {@link X509BundleSet} that are updated automatically
 * whenever there is an update from the Workload API.
 * <p>
 * It implements the Closeable interface. The {@link #close()} method closes the source,
 * dropping the connection to the Workload API. Other source methods will return an error
 * after close has been called.
 */
@Log
public class X509Source implements X509SvidSource, X509BundleSource, Closeable {

    private X509Svid svid;
    private X509BundleSet bundles;

    private Function<List<X509Svid>, X509Svid> picker;
    private WorkloadApiClient workloadApiClient;
    private volatile boolean closed;

    /**
     * Creates a new X509Source. It blocks until the initial update
     * has been received from the Workload API.
     * <p>
     * It uses the Default Address from the Environment variable to get the Workload API endpoint address.
     * <p>
     * It uses the default X509-SVID.
     *
     * @return an initialized an {@link spiffe.result.Ok} with X509Source, or an {@link Error} in
     * case the X509Source could not be initialized.
     */
    public static Result<X509Source, String> newSource() {
        X509SourceOptions x509SourceOptions = X509SourceOptions.builder().build();
        return newSource(x509SourceOptions);
    }

    /**
     * Creates a new X509Source. It blocks until the initial update
     * has been received from the Workload API.
     * <p>
     * The {@link WorkloadApiClient} can be provided in the options, if it is not,
     * a new client is created.
     *
     * @param options {@link X509SourceOptions}
     * @return an initialized an {@link spiffe.result.Ok} with X509Source, or an {@link Error} in
     * case the X509Source could not be initialized.
     */
    public static Result<X509Source, String> newSource(@NonNull X509SourceOptions options) {

        if (options.workloadApiClient == null) {
            Result<WorkloadApiClient, String> workloadApiClient = createClient(options);
            if (workloadApiClient.isError()) {
                return Result.error(workloadApiClient.getError());
            }
            options.workloadApiClient = workloadApiClient.getValue();
        }

        val x509Source = new X509Source();
        x509Source.picker = options.picker;
        x509Source.workloadApiClient = options.workloadApiClient;

        Result<Boolean, String> init = x509Source.init();
        if (init.isError()) {
            x509Source.close();
            return Result.error("Error creating X509 Source: %s", init.getError());
        }

        return Result.ok(x509Source);
    }

    private static Result<WorkloadApiClient, String> createClient(@NonNull X509Source.@NonNull X509SourceOptions options) {
        Result<WorkloadApiClient, String> workloadApiClient;
        val clientOptions= WorkloadApiClient.ClientOptions
                .builder()
                .spiffeSocketPath(options.spiffeSocketPath)
                .build();
        workloadApiClient = WorkloadApiClient.newClient(clientOptions);
        return workloadApiClient;
    }

    private X509Source() {
    }

    /**
     * Returns the X509-SVID handled by this source, returns an Error in case
     * the source is already closed.
     *
     * @return an {@link spiffe.result.Ok} containing the {@link X509Svid}
     */
    @Override
    public Result<X509Svid, String> getX509Svid() {
        val checkClosed = checkClosed();
        if (checkClosed.isError()) {
            return Result.error(checkClosed.getError());
        }
        return Result.ok(svid);
    }

    /**
     * Returns the X509-Bundle for a given trust domain, returns an Error in case
     * there is no bundle for the trust domain, or the source is already closed.
     *
     * @return an {@link spiffe.result.Ok} containing the {@link X509Bundle}.
     */
    @Override
    public Result<X509Bundle, String> getX509BundleForTrustDomain(@NonNull final TrustDomain trustDomain) {
        val checkClosed = checkClosed();
        if (checkClosed.isError()) {
            return Result.error(checkClosed.getError());
        }
        return bundles.getX509BundleForTrustDomain(trustDomain);
    }

    /**
     * Closes this source, dropping the connection to the Workload API.
     * Other source methods will return an error after close has been called.
     */
    @Override
    public void close() {
        if (!closed) {
            synchronized (this) {
                if (!closed) {
                    workloadApiClient.close();
                    closed = true;
                }
            }
        }

    }

    private Result<Boolean, String> init() {
        Result<X509Context, String> x509Context = workloadApiClient.fetchX509Context();
        if (x509Context.isError()) {
            return Result.error(x509Context.getError());
        }
        setX509Context(x509Context.getValue());
        setX509ContextWatcher();
        return Result.ok(true);
    }

    private void setX509ContextWatcher() {
        workloadApiClient.watchX509Context(new Watcher<X509Context>() {
            @Override
            public void OnUpdate(X509Context update) {
                log.log(Level.INFO, "Received X509Context update");
                setX509Context(update);
            }

            @Override
            public void OnError(Error<X509Context, String> error) {
                log.log(Level.SEVERE, String.format("Error in X509Context watcher: %s", error.getError()));
            }
        });
    }

    private void setX509Context(@NonNull final X509Context update) {
        X509Svid svid;
        if (picker == null) {
            svid = update.getDefaultSvid();
        } else {
            svid = picker.apply(update.getX509Svid());
        }
        synchronized (this) {
            this.svid = svid;
            this.bundles = update.getX509BundleSet();
        }
    }

    private Result<Boolean, String> checkClosed() {
        synchronized (this) {
            if (closed) {
                return Result.error("source is closed");
            }
            return Result.ok(true);
        }
    }

    /**
     * Options for creating a new {@link X509Source}
     */
    @Data
    public static class X509SourceOptions {
        String spiffeSocketPath;
        Function<List<X509Svid>, X509Svid> picker;
        WorkloadApiClient workloadApiClient;

        @Builder
        public X509SourceOptions(String spiffeSocketPath, Function<List<X509Svid>, X509Svid> picker, WorkloadApiClient workloadApiClient) {
            this.spiffeSocketPath = spiffeSocketPath;
            this.picker = picker;
            this.workloadApiClient = workloadApiClient;
        }
    }
}
