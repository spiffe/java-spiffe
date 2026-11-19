package io.spiffe.workloadapi.internal.linux;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NegotiationType;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.channel.ChannelOption;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollDomainSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress;
import io.spiffe.workloadapi.internal.GrpcChannelProvider;
import io.spiffe.workloadapi.internal.ManagedChannelWrapper;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

/**
 * {@link GrpcChannelProvider} for Linux, based on the Netty epoll transport.
 */
public final class LinuxGrpcChannelProvider implements GrpcChannelProvider {

    private static final String UNIX_SCHEME = "unix";
    private static final String TCP_SCHEME = "tcp";

    @Override
    public boolean isSupported() {
        return SystemUtils.IS_OS_LINUX;
    }

    @Override
    public ManagedChannelWrapper newChannel(URI address, ExecutorService executorService) {
        Objects.requireNonNull(address, "address must not be null");

        String scheme = address.getScheme();
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
    private ManagedChannelWrapper createNativeSocketChannel(URI address, ExecutorService executorService) {
        if (!isSupported()) {
            throw new IllegalStateException("Operating System is not supported.");
        }

        // nThreads = 0 -> use Netty default
        EpollEventLoopGroup eventLoopGroup = new EpollEventLoopGroup(0, executorService);
        ManagedChannel managedChannel = NettyChannelBuilder.forAddress(new DomainSocketAddress(address.getPath()))
                .eventLoopGroup(eventLoopGroup)
                // avoid warning Unknown channel option 'SO_KEEPALIVE'
                .withOption(ChannelOption.SO_KEEPALIVE, null)
                .channelType(EpollDomainSocketChannel.class)
                .usePlaintext()
                .build();
        return new ManagedChannelWrapper(managedChannel, eventLoopGroup::shutdownGracefully);
    }

    private ManagedChannelWrapper createTcpChannel(URI address) {
        ManagedChannel managedChannel = NettyChannelBuilder.forAddress(address.getHost(), address.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
        return new ManagedChannelWrapper(managedChannel);
    }
}
