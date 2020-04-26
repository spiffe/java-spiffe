package spiffe.workloadapi;

import lombok.val;
import org.apache.commons.lang3.StringUtils;
import spiffe.exception.SocketEndpointAddressException;

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
     * 	Environment variable holding the default Workload API address.
     */
    public static final String SOCKET_ENV_VARIABLE = "SPIFFE_ENDPOINT_SOCKET";

    private static final List<String> VALID_SCHEMES = Arrays.asList("unix", "tcp");

    /**
     * Returns the default Workload API address hold by the system environment variable
     * defined by SOCKET_ENV_VARIABLE
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
     *
     * @throws SocketEndpointAddressException if the address could not be parsed or if it is not valid
     */
    public static URI parseAddress(String address) throws SocketEndpointAddressException {
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
        switch (scheme) {
            case "unix": {
                if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
                    error = "Workload endpoint unix socket URI must not be opaque: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
                    error = "Workload endpoint unix socket URI must not include user info: %s";
                    break;
                }

                if (StringUtils.isBlank(parsedAddress.getHost()) && StringUtils.isBlank(parsedAddress.getPath())) {
                    error = "Workload endpoint unix socket URI must include a path: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
                    error = "Workload endpoint unix socket URI must not include query values: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
                    error = "Workload endpoint unix socket URI must not include a fragment: %s";
                }
                break;
            }

            case "tcp": {
                if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
                    error = "Workload endpoint tcp socket URI must not be opaque: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
                    error = "Workload endpoint tcp socket URI must not include user info: %s";
                    break;
                }

                if (StringUtils.isBlank(parsedAddress.getHost())) {
                    error = "Workload endpoint tcp socket URI must include a host: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getPath())) {
                    error = "Workload endpoint tcp socket URI must not include a path: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
                    error = "Workload endpoint tcp socket URI must not include query values: %s";
                    break;
                }

                if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
                    error = "Workload endpoint tcp socket URI must not include a fragment: %s";
                    break;
                }

                String ip = parseIp(parsedAddress.getHost());
                if (StringUtils.isBlank(ip)) {
                    error = "Workload endpoint tcp socket URI host component must be an IP:port: %s";
                    break;
                }

                int port = parsedAddress.getPort();
                if (port == -1) {
                    error = "Workload endpoint tcp socket URI host component must include a port: %s";
                }
                break;
            }
        }

        if (StringUtils.isNotBlank(error)) {
            throw new SocketEndpointAddressException(String.format(error, address));
        }

        return parsedAddress;
    }

    private static boolean isValid(String scheme) {
        return (StringUtils.isNotBlank(scheme) && VALID_SCHEMES.contains(scheme));
    }

    private static String parseIp(String host) {
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
