package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import lombok.NonNull;
import lombok.val;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.util.concurrent.ExecutorService;

/**
 * Factory for creating ManagedChannel instances for Mac OS.
 */
public final class GrpcManagedChannelFactory {

    private static final String UNIX_SCHEME = "unix";
    private static final String TCP_SCHEME = "tcp";

    private GrpcManagedChannelFactory() {
    }

    /**
     * Returns a ManagedChannelWrapper that contains a {@link ManagedChannel} to the SPIFFE Socket Endpoint provided.
     *
     * @param address         URI representing the Workload API endpoint.
     * @param executorService the executor to configure the event loop group
     * @return a instance of a {@link ManagedChannelWrapper}
     */
    public static ManagedChannelWrapper newChannel(@NonNull URI address, ExecutorService executorService) {
        val scheme = address.getScheme();
        ManagedChannelWrapper result;
        switch (scheme) {
            case UNIX_SCHEME:
                result = createNativeSocketChannel(address, executorService);
                break;
            case TCP_SCHEME:
                result = createTcpChannel(address);
                break;
            default:
                throw new IllegalArgumentException("Address Scheme not supported: ");
        }
        return result;
    }

    // Create a Native Socket Channel pointing to the spiffeSocketPath
    private static ManagedChannelWrapper createNativeSocketChannel(@NonNull URI address, ExecutorService executorService) {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(address.getPath()));
        EventLoopGroup eventLoopGroup = configureNativeSocketChannel(channelBuilder, executorService);
        ManagedChannel managedChannel = channelBuilder.usePlaintext().build();
        return new ManagedChannelWrapper(managedChannel, eventLoopGroup);
    }

    private static ManagedChannelWrapper createTcpChannel(@NonNull URI address) {
        ManagedChannel managedChannel = NettyChannelBuilder.forAddress(address.getHost(), address.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
        return new ManagedChannelWrapper(managedChannel);
    }

    private static EventLoopGroup configureNativeSocketChannel(@NonNull NettyChannelBuilder channelBuilder, ExecutorService executorService) {
        if (SystemUtils.IS_OS_MAC) {
            // nThreads = 0 -> use Netty default
            KQueueEventLoopGroup eventLoopGroup = new KQueueEventLoopGroup(0, executorService);
            channelBuilder.eventLoopGroup(eventLoopGroup)
                    // avoid warning Unknown channel option 'SO_KEEPALIVE'
                    .withOption(ChannelOption.SO_KEEPALIVE, null)
                    .channelType(KQueueDomainSocketChannel.class);
            return eventLoopGroup;
        }

        throw new IllegalStateException("Operating System is not supported.");
    }
}