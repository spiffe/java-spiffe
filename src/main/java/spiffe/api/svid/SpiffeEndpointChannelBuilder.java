package spiffe.api.svid;

import io.grpc.*;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.kqueue.KQueueServerDomainSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 *  Encapsulates the logic for creating the ManagedBuilder
 *  Resolves the Address from Env if it's not provided as parameter.
 *  Based on the Address scheme, creates a TCP or a Native Socket Channel
 *  Configures the Socket Channel based on the detected OS
 *
 */
class SpiffeEndpointChannelBuilder {

    static final String ENV_ADDRESS_VAR = "SPIFFE_ENDPOINT_SOCKET";

    /**
     * Returns a configured ManagedChannel
     * @param spiffeEndpointAddress
     * @return
     */
    static ManagedChannel newChannel(String spiffeEndpointAddress) {
        if (isBlank(spiffeEndpointAddress)) {
            spiffeEndpointAddress = getAddressFromEnv();
        }

        URI parsedAddress = parseAddress(spiffeEndpointAddress);
        if (isTcp(parsedAddress)) {
            return createTcpChannel(parsedAddress);
        } else {
            return createNativeSocketChannel(spiffeEndpointAddress);
        }
    }

    /**
     * Try to resolve the Address from the Environment.
     * @throws IllegalStateException if the Address is not found
     * @return the Address
     */
    private static String getAddressFromEnv() {
        String address = System.getenv(ENV_ADDRESS_VAR);
        if (isBlank(address)) {
            throw new IllegalStateException(ENV_ADDRESS_VAR + " env var is not defined");
        }
        return address;
    }

    /**
     * Create a TCP channel based on the given URI
     *
     * @param parsedAddress
     * @return
     */
    private static ManagedChannel createTcpChannel(URI parsedAddress) {
        return NettyChannelBuilder.forAddress(parsedAddress.getHost(), parsedAddress.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
    }

    /**
     * Create a Native Socket Channel pointing to the spiffeEndpointAddress
     * @param spiffeEndpointAddress
     * @return
     */
    private static ManagedChannel createNativeSocketChannel(String spiffeEndpointAddress) {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(spiffeEndpointAddress));
        configureNativeSocketChannel(channelBuilder);
        return channelBuilder
                .usePlaintext()
                .build();
    }

    /**
     * Based on the detected OS, configures the Socket Channel EventLookGroup and Channel Type
     *
     * @param channelBuilder
     */
    private static void configureNativeSocketChannel(NettyChannelBuilder channelBuilder) {
        if (SystemUtils.IS_OS_LINUX) {
            channelBuilder.eventLoopGroup(new EpollEventLoopGroup())
                          .channelType(EpollDomainSocketChannel.class);
        } else if (SystemUtils.IS_OS_MAC) {
            channelBuilder.eventLoopGroup(new KQueueEventLoopGroup())
                          .channelType(KQueueServerDomainSocketChannel.class);
        } else {
            channelBuilder.eventLoopGroup(new NioEventLoopGroup());
        }
    }

    private static URI parseAddress(String spiffeEndpointAddress) {
        URI parsedAddress;
        try {
            parsedAddress = new URI(spiffeEndpointAddress);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("The Spiffe Endopoint Address is not valid");
        }
        return parsedAddress;
    }

    private static boolean isTcp(URI spiffeEndpointAddress) {
        return "tcp".equalsIgnoreCase(spiffeEndpointAddress.getScheme());
    }
}