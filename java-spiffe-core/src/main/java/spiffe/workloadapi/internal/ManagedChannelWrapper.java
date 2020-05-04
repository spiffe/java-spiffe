package spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.netty.channel.EventLoopGroup;

import java.io.Closeable;

/**
 * Wraps a ManagedChannel along with the EventLoopGroup in order to
 * have more control and be able to shutdown the channel properly
 * calling the shutdownGracefully on the EventLoopGroup to prevent
 * that some threads remain active.
 */
public class ManagedChannelWrapper implements Closeable {

    private final ManagedChannel managedChannel;
    private final EventLoopGroup eventLoopGroup;

    public ManagedChannelWrapper(ManagedChannel managedChannel, EventLoopGroup eventLoopGroup) {
        this.managedChannel = managedChannel;
        this.eventLoopGroup = eventLoopGroup;
    }

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
