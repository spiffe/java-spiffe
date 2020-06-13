package spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NegotiationType;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.channel.ChannelOption;
import io.grpc.netty.shaded.io.netty.channel.EventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress;
import lombok.NonNull;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.util.concurrent.ExecutorService;

/**
 * Factory for creating ManagedChannel instances.
 */
public class GrpcManagedChannelFactory {

    /**
     * Returns a ManagedChannelWrapper with a Channel to the Spiffe Socket Endpoint provided.
     *
     * @param address         URI representing the Workload API endpoint.
     * @param executorService the executor to configure the event loop group
     * @return a instance of a {@link ManagedChannel}
     */
    public static ManagedChannelWrapper newChannel(@NonNull URI address, ExecutorService executorService) {
        if ("unix".equals(address.getScheme())) {
            return createNativeSocketChannel(address, executorService);
        } else {
            return createTcpChannel(address);
        }
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