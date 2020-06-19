package io.spiffe.workloadapi;

import io.spiffe.exception.SocketEndpointAddressException;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class to get the default Workload API address and parse string addresses.
 */
public class Address {

    /**
     * Environment variable holding the default Workload API address.
     */
    public static final String SOCKET_ENV_VARIABLE = "SPIFFE_ENDPOINT_SOCKET";

    private static final String UNIX_SCHEME = "unix";
    private static final String TCP_SCHEME = "tcp";
    private static final List<String> VALID_SCHEMES = Arrays.asList(UNIX_SCHEME, TCP_SCHEME);

    /**
     * @return the default Workload API address hold by the system environment variable
     * defined by SOCKET_ENV_VARIABLE.
     */
    public static String getDefaultAddress() {
        return System.getenv(Address.SOCKET_ENV_VARIABLE);
    }

    /**
     * Parses and validates a Workload API socket address.
     * <p>
     * The given address should either have a tcp, or a unix scheme.
     * <p>
     * The given address should contain a path.
     * <p>
     * The given address cannot be opaque, cannot have fragments, query values or user info.
     * <p>
     * If the given address is tcp, it should contain an IP and a port.
     *
     * @param address the Workload API socket address as a string
     * @return an instance of a {@link URI}
     * @throws SocketEndpointAddressException if the address could not be parsed or if it is not valid
     */
    public static URI parseAddress(final String address) throws SocketEndpointAddressException {

        URI parsedAddress;

        try {
            parsedAddress = new URI(address);
        } catch (URISyntaxException e) {
            throw new SocketEndpointAddressException(String.format("Workload endpoint socket is not a valid URI: %s", address), e);
        }

        val scheme = parsedAddress.getScheme();
        if (!isValid(scheme)) {
            throw new SocketEndpointAddressException(String.format("Workload endpoint socket URI must have a tcp:// or unix:// scheme: %s", address));
        }

        String error = null;
        if (UNIX_SCHEME.equals(scheme)) {
            error = validateUnixAddress(parsedAddress);
        }

        if (TCP_SCHEME.equals(scheme)) {
            error = validateTcpAddress(parsedAddress);
        }

        if (StringUtils.isNotBlank(error)) {
            throw new SocketEndpointAddressException(String.format(error, address));
        }

        return parsedAddress;
    }

    private static String validateUnixAddress(final URI parsedAddress) {
        if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
            return "Workload endpoint unix socket URI must not be opaque: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
            return "Workload endpoint unix socket URI must not include user info: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
            return "Workload endpoint unix socket URI must not include query values: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
            return "Workload endpoint unix socket URI must not include a fragment: %s";
        }
        return "";
    }

    private static String validateTcpAddress(final URI parsedAddress) {
        if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
            return "Workload endpoint tcp socket URI must not be opaque: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
            return "Workload endpoint tcp socket URI must not include user info: %s";
        }

        if (StringUtils.isBlank(parsedAddress.getHost())) {
            return "Workload endpoint tcp socket URI must include a host: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getPath())) {
            return "Workload endpoint tcp socket URI must not include a path: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
            return "Workload endpoint tcp socket URI must not include query values: %s";
        }

        if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
            return "Workload endpoint tcp socket URI must not include a fragment: %s";
        }

        String ip = parseIp(parsedAddress.getHost());
        if (StringUtils.isBlank(ip)) {
            return "Workload endpoint tcp socket URI host component must be an IP:port: %s";
        }

        int port = parsedAddress.getPort();
        if (port == -1) {
            return "Workload endpoint tcp socket URI host component must include a port: %s";
        }
        return "";
    }

    private static boolean isValid(final String scheme) {
        return StringUtils.isNotBlank(scheme) && VALID_SCHEMES.contains(scheme);
    }

    private static String parseIp(final String host) {
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private Address() {
    }
}
