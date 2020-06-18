package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.netty.channel.EventLoopGroup;

import java.io.Closeable;

/**
 * Wraps a {@link ManagedChannel} along with the {@link EventLoopGroup} in order to
 * have more control and be able to shutdown the channel properly
 * calling the shutdownGracefully method on the EventLoopGroup to prevent
 * that some threads remain active.
 */
public class ManagedChannelWrapper implements Closeable {

    private final ManagedChannel managedChannel;
    private final EventLoopGroup eventLoopGroup;

    /**
     * Constructor
     *
     * @param  managedChannel an instance of {@link ManagedChannel}
     * @param eventLoopGroup an instance of {@link EventLoopGroup}
     */
    public ManagedChannelWrapper(ManagedChannel managedChannel, EventLoopGroup eventLoopGroup) {
        this.managedChannel = managedChannel;
        this.eventLoopGroup = eventLoopGroup;
    }

    /**
     * Constructor
     *
     * @param managedChannel a {@link ManagedChannel}
     */
    public ManagedChannelWrapper(ManagedChannel managedChannel) {
        this.managedChannel = managedChannel;
        this.eventLoopGroup = null;
    }

    @Override
    public void close() {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully();
        }
        managedChannel.shutdown();
    }

    public ManagedChannel getChannel() {
        return managedChannel;
    }
}
