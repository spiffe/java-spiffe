package io.spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NegotiationType;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.channel.ChannelOption;
import io.grpc.netty.shaded.io.netty.channel.EventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress;
import io.spiffe.workloadapi.AddressScheme;
import lombok.NonNull;
import lombok.val;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.util.concurrent.ExecutorService;

import static io.spiffe.workloadapi.AddressScheme.UNIX_SCHEME;

/**
 * Factory for creating ManagedChannel instances.
 * <p>
 * Only Linux is supported since the recommended grpc-netty-shaded library only supports <code>EpollEventLoopGroup</code>.
 * @see <a href="https://github.com/grpc/grpc-java">Grpc Java Library</a>
 * @see <a href="https://github.com/spiffe/java-spiffe/issues/32">Support MacOS</a>
 */
public class GrpcManagedChannelFactory {

    /**
     * Returns a ManagedChannelWrapper that contains a {@link ManagedChannel} to the SPIFFE Socket Endpoint provided.
     *
     * @param address         URI representing the Workload API endpoint.
     * @param executorService the executor to configure the event loop group
     * @return a instance of a {@link ManagedChannelWrapper}
     */
    public static ManagedChannelWrapper newChannel(@NonNull URI address, ExecutorService executorService) {
        ManagedChannelWrapper result;
        val scheme = AddressScheme.parseScheme(address.getScheme());
        if (scheme == UNIX_SCHEME) {
            result = createNativeSocketChannel(address, executorService);
        } else {
            result = createTcpChannel(address);
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

    private GrpcManagedChannelFactory() {}
}