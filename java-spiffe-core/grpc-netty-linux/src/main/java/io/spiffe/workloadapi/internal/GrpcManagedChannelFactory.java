package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NegotiationType;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.channel.ChannelOption;
import io.grpc.netty.shaded.io.netty.channel.EventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

/**
 * Factory for creating ManagedChannel instances for Linux OS.
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
    public static ManagedChannelWrapper newChannel(URI address, ExecutorService executorService) {
        Objects.requireNonNull(address, "address must not be null");

        final String scheme = address.getScheme();
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
    private static ManagedChannelWrapper createNativeSocketChannel(URI address, ExecutorService executorService) {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(address.getPath()));
        EventLoopGroup eventLoopGroup = configureNativeSocketChannel(channelBuilder, executorService);
        ManagedChannel managedChannel = channelBuilder.usePlaintext().build();
        return new ManagedChannelWrapper(managedChannel, eventLoopGroup);
    }

    private static ManagedChannelWrapper createTcpChannel(URI address) {
        ManagedChannel managedChannel = NettyChannelBuilder.forAddress(address.getHost(), address.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
        return new ManagedChannelWrapper(managedChannel);
    }

    private static EventLoopGroup configureNativeSocketChannel(NettyChannelBuilder channelBuilder, ExecutorService executorService) {
        if (SystemUtils.IS_OS_LINUX) {
            // nThreads = 0 -> use Netty default
            EpollEventLoopGroup epollEventLoopGroup = new EpollEventLoopGroup(0, executorService);
            channelBuilder.eventLoopGroup(epollEventLoopGroup)
                    // avoid warning Unknown channel option 'SO_KEEPALIVE'
                    .withOption(ChannelOption.SO_KEEPALIVE, null)
                    .channelType(EpollDomainSocketChannel.class);
            return epollEventLoopGroup;
        }

        throw new IllegalStateException("Operating System is not supported.");
    }
}