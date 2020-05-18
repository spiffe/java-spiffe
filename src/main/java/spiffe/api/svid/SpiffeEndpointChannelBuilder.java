package spiffe.api.svid;

import io.grpc.*;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.ChannelOption;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import org.apache.commons.lang3.SystemUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static java.lang.String.format;
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
    static final String ADDRESS_PROPERTY = "spiffe.endpoint.socket";

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
        }

        validateUDSAddress(parsedAddress);
        return createNativeSocketChannel(parsedAddress);
    }

    /**
     * Resolve the Address from the Environment.
     * First it looks in the JVM Properties (can be passed as -Dspiffe.endpoint.socket)
     * Then if looks if it's defined as a System Variable
     *
     * @throws IllegalStateException if the Address is not found
     * @return the Address
     */
    private static String getAddressFromEnv() {
        String address = System.getProperty(ADDRESS_PROPERTY);
        if (!isBlank(address)) {
            return address;
        }
        address = System.getenv(ENV_ADDRESS_VAR);
        if (isBlank(address)) {
            throw new IllegalStateException(format("%s env var is not defined", ENV_ADDRESS_VAR ));
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
        checkNotNull(parsedAddress, "UDS address is null" );
        return NettyChannelBuilder.forAddress(parsedAddress.getHost(), parsedAddress.getPort())
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();
    }

    /**
     * Create a Native Socket Channel pointing to the spiffeEndpointAddress
     * @param spiffeEndpointAddress
     * @return
     */
    private static ManagedChannel createNativeSocketChannel(URI spiffeEndpointAddress) {
        checkNotNull(spiffeEndpointAddress, "UDS address is null" );
        NettyChannelBuilder channelBuilder = NettyChannelBuilder.
                forAddress(new DomainSocketAddress(spiffeEndpointAddress.getPath()));
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
        checkNotNull(channelBuilder, "Channel builder is Null");
        if (SystemUtils.IS_OS_LINUX) {
            channelBuilder.eventLoopGroup(new EpollEventLoopGroup())
                    // avoid Unknown channel option 'SO_KEEPALIVE'
                    .withOption(ChannelOption.SO_KEEPALIVE, null)
                    .channelType(EpollDomainSocketChannel.class);
        } else if (SystemUtils.IS_OS_MAC) {
            channelBuilder.eventLoopGroup(new KQueueEventLoopGroup())
                    .withOption(ChannelOption.SO_KEEPALIVE, null)
                    .channelType(KQueueDomainSocketChannel.class);
        } else {
            channelBuilder.eventLoopGroup(new NioEventLoopGroup());
        }
    }

    private static URI parseAddress(String spiffeEndpointAddress) {
        URI parsedAddress;
        try {
            parsedAddress = new URI(spiffeEndpointAddress);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("The Spiffe Endpoint Address is not valid");
        }
        return parsedAddress;
    }

    private static void validateUDSAddress(URI address) {
        checkNotNull(address, "UDS address is null" );
        checkState(isBlank(address.getHost()),
                format("Unexpected Authority component in Unix uri: %s", address.getHost() ) );
        checkState(!isBlank(address.getPath()), "No Path defined for Unix uri");
        checkState(address.getPath().startsWith("/"), "Unix Socket Path not absolute");
    }

    private static boolean isTcp(URI spiffeEndpointAddress) {
        return "tcp".equalsIgnoreCase(spiffeEndpointAddress.getScheme());
    }
}