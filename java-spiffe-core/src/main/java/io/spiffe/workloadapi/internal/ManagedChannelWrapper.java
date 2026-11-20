package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;

import java.io.Closeable;

/**
 * Wraps a {@link ManagedChannel} along with a hook that releases the transport resources behind it,
 * such as the Netty event loop group, so that closing the channel doesn't leave threads behind.
 */
public class ManagedChannelWrapper implements Closeable {

    private final ManagedChannel managedChannel;
    private final Runnable onClose;

    /**
     * Constructor.
     *
     * @param managedChannel an instance of {@link ManagedChannel}
     * @param onClose        called when this wrapper is closed, before the channel is shut down
     */
    public ManagedChannelWrapper(ManagedChannel managedChannel, Runnable onClose) {
        this.managedChannel = managedChannel;
        this.onClose = onClose;
    }

    /**
     * Constructor.
     *
     * @param managedChannel a {@link ManagedChannel}
     */
    public ManagedChannelWrapper(ManagedChannel managedChannel) {
        this(managedChannel, null);
    }

    @Override
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
        managedChannel.shutdown();
    }

    public ManagedChannel getChannel() {
        return managedChannel;
    }
}
