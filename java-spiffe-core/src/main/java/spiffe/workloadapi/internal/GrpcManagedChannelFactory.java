package spiffe.workloadapi.internal;

import io.grpc.ManagedChannel;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import lombok.NonNull;
import lombok.val;
import org.apache.commons.lang3.SystemUtils;
import spiffe.result.Result;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for creating and handling ManagedChannel instances
 * keyed by Spiffe Socket Paths.
 * If a ManagedChannel exists for a SpiffeSocketPath, returns that instance,
 * otherwise create a new instance and cache it.
 *
 */
public class GrpcManagedChannelFactory {

    private static final Map<Path, ManagedChannel> managedChannels = new HashMap<>();

    /**
     * Return a ManagedChannel to the Spiffe Socket Endpoint provided.
     *
     * @param spiffeSocketPath Path to the Workload API endpoint.
     * @return a instance of a ManagedChannel.
     */
    public static Result<ManagedChannel, Throwable> getManagedChannel(Path spiffeSocketPath) {
        synchronized (GrpcManagedChannelFactory.class) {
            if (managedChannels.containsKey(spiffeSocketPath)) {
                return Result.ok(managedChannels.get(spiffeSocketPath));
            }
            val channel = newChannel(spiffeSocketPath);
            if (channel.isError()) {
                return Result.error(channel.getError());
            }
            managedChannels.put(spiffeSocketPath, channel.getValue());
            return channel;
        }
    }

    private static Result<ManagedChannel, Throwable> newChannel(Path spiffeSocketPath) {
        Result<URI, Throwable> parsedAddress = parseAddress(spiffeSocketPath.toString());
        if (parsedAddress.isError()) {
            return Result.error(parsedAddress.getError());
        }

        ManagedChannel nativeSocketChannel = createNativeSocketChannel(parsedAddress.getValue());
        return Result.ok(nativeSocketChannel);
    }

    // Create a Native Socket Channel pointing to the spiffeSocketPath
    private static ManagedChannel createNativeSocketChannel(@NonNull URI spiffeSocketPath) {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(spiffeSocketPath.getPath()));
        configureNativeSocketChannel(channelBuilder);
        return channelBuilder
                .usePlaintext()
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

    private static Result<URI, Throwable> parseAddress(String spiffeSocketPath) {
        URI parsedAddress;
        try {
            parsedAddress = new URI(spiffeSocketPath);
        } catch (URISyntaxException e) {
            return Result.error(new IllegalArgumentException("The Spiffe Endpoint Address is not valid"));
        }
        return Result.ok(parsedAddress);
    }
}