package io.spiffe.workloadapi.internal;

import java.net.URI;
import java.util.Iterator;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;

/**
 * Factory for creating ManagedChannel instances, using the {@link GrpcChannelProvider} found on the
 * classpath for the current platform.
 */
public final class GrpcManagedChannelFactory {

    private static volatile GrpcChannelProvider provider;

    private GrpcManagedChannelFactory() {
    }

    /**
     * Returns a ManagedChannelWrapper that contains a {@link io.grpc.ManagedChannel} to the SPIFFE
     * Socket Endpoint provided.
     *
     * @param address         URI representing the Workload API endpoint.
     * @param executorService the executor to configure the event loop group
     * @return a instance of a {@link ManagedChannelWrapper}
     * @throws IllegalStateException if no grpc-netty module is on the classpath
     */
    public static ManagedChannelWrapper newChannel(URI address, ExecutorService executorService) {
        Objects.requireNonNull(address, "address must not be null");
        return getProvider().newChannel(address, executorService);
    }

    private static GrpcChannelProvider getProvider() {
        GrpcChannelProvider result = provider;
        if (result == null) {
            result = selectProvider(loadProviders());
            provider = result;
        }
        return result;
    }

    private static Iterator<GrpcChannelProvider> loadProviders() {
        return ServiceLoader.load(GrpcChannelProvider.class, GrpcChannelProvider.class.getClassLoader()).iterator();
    }

    /**
     * Picks the first provider that supports the current platform. If none does, the first provider
     * found is used, so TCP addresses keep working and Unix socket addresses fail with the provider's
     * own error, as they did before providers were looked up.
     */
    static GrpcChannelProvider selectProvider(Iterator<GrpcChannelProvider> providers) {
        GrpcChannelProvider first = null;
        while (hasNext(providers)) {
            GrpcChannelProvider candidate;
            try {
                candidate = providers.next();
            } catch (ServiceConfigurationError e) {
                // a provider that can't be loaded (e.g. a broken jar) shouldn't hide the others
                continue;
            }
            if (candidate.isSupported()) {
                return candidate;
            }
            if (first == null) {
                first = candidate;
            }
        }

        if (first == null) {
            throw new IllegalStateException("No gRPC channel provider found on the classpath. Add one of the "
                    + "io.spiffe:grpc-netty-linux, io.spiffe:grpc-netty-macos or io.spiffe:grpc-netty-macos-aarch64 "
                    + "modules as a runtime dependency.");
        }
        return first;
    }

    private static boolean hasNext(Iterator<GrpcChannelProvider> providers) {
        try {
            return providers.hasNext();
        } catch (ServiceConfigurationError e) {
            return false;
        }
    }
}
