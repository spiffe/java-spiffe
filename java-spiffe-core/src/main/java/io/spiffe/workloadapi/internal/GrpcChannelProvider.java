package io.spiffe.workloadapi.internal;

import java.net.URI;
import java.util.concurrent.ExecutorService;

/**
 * Creates the gRPC channels used to talk to the Workload API.
 * <p>
 * Implementations live in the platform specific {@code grpc-netty-*} modules and are registered in
 * {@code META-INF/services/io.spiffe.workloadapi.internal.GrpcChannelProvider}, so they are found
 * with {@link java.util.ServiceLoader} instead of by sharing a class name with core.
 */
public interface GrpcChannelProvider {

    /**
     * Returns whether this provider can open Unix domain socket channels on the current OS and
     * architecture.
     *
     * @return true if this provider supports the current platform
     */
    boolean isSupported();

    /**
     * Returns a ManagedChannelWrapper that contains a {@link io.grpc.ManagedChannel} to the SPIFFE
     * Socket Endpoint provided.
     *
     * @param address         URI representing the Workload API endpoint
     * @param executorService the executor to configure the event loop group
     * @return an instance of a {@link ManagedChannelWrapper}
     */
    ManagedChannelWrapper newChannel(URI address, ExecutorService executorService);
}
