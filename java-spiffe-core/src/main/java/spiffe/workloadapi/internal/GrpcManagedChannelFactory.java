package spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import lombok.NonNull;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;

/**
 * Factory for creating ManagedChannel instances.
 */
public class GrpcManagedChannelFactory {

    /**
     * Return a ManagedChannel to the Spiffe Socket Endpoint provided.
     *
     * @param address URI representing the Workload API endpoint.
     * @return a instance of a {@link ManagedChannel}
     */
    public static ManagedChannel newChannel(@NonNull URI address) {
        if ("unix".equals(address.getScheme())) {
            return createNativeSocketChannel(address);
        } else {
            return createTcpChannel(address);
        }
    }

    // Create a Native Socket Channel pointing to the spiffeSocketPath
    private static ManagedChannel createNativeSocketChannel(@NonNull URI address) {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(address.getPath()));
        configureNativeSocketChannel(channelBuilder);
        return channelBuilder
                .usePlaintext()
                .build();
    }

    private static ManagedChannel createTcpChannel(@NonNull URI address) {
        return NettyChannelBuilder.forAddress(address.getHost(), address.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
    }

    // Based on the detected OS, configures the Socket Channel EventLookGroup and Channel Type
    private static void configureNativeSocketChannel(@NonNull NettyChannelBuilder channelBuilder) {
        if (SystemUtils.IS_OS_LINUX) {
            channelBuilder.eventLoopGroup(new EpollEventLoopGroup())
                    .channelType(EpollDomainSocketChannel.class);
            return;
        }

        if (SystemUtils.IS_OS_MAC) {
            channelBuilder.eventLoopGroup(new KQueueEventLoopGroup())
                    .channelType(KQueueDomainSocketChannel.class);
            return;
        }

        channelBuilder.eventLoopGroup(new NioEventLoopGroup());
    }

    private GrpcManagedChannelFactory() {}
}