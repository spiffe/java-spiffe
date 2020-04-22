package spiffe.workloadapi;

import org.apache.commons.lang3.StringUtils;
import spiffe.result.Result;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Utility class to get the default Workload api address and parse string addresses.
 */
public class Address {

    /**
     * 	Environment variable holding the default Workload API address.
     */
    public static final String SOCKET_ENV_VARIABLE = "SPIFFE_ENDPOINT_SOCKET";

    public static String getDefaultAddress() {
        return System.getenv(Address.SOCKET_ENV_VARIABLE);
    }

    public static Result<URI, String> parseAddress(String addr) {
        URI parsedAddress;
        try {
            parsedAddress = new URI(addr);
        } catch (URISyntaxException e) {
            return Result.error("Workload endpoint socket is not a valid URI: %s", e.getMessage());
        }

        if (parsedAddress.getScheme() == null) {
            return Result.error("Workload endpoint socket URI must have a tcp:// or unix:// scheme");
        }

        switch (parsedAddress.getScheme()) {
            case "unix": {
                if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
                    return Result.error("Workload endpoint unix socket URI must not be opaque");
                }

                if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
                    return Result.error("Workload endpoint unix socket URI must not include user info");
                }

                if (StringUtils.isBlank(parsedAddress.getHost()) && StringUtils.isBlank(parsedAddress.getPath())) {
                    return Result.error("Workload endpoint unix socket URI must include a path");
                }

                if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
                    return Result.error("Workload endpoint unix socket URI must not include query values");
                }

                if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
                    return Result.error("Workload endpoint unix socket URI must not include a fragment");
                }

                return Result.ok(parsedAddress);

            }

            case "tcp": {
                if (parsedAddress.isOpaque() && parsedAddress.isAbsolute()) {
                    return Result.error("Workload endpoint tcp socket URI must not be opaque");
                }

                if (StringUtils.isNotBlank(parsedAddress.getUserInfo())) {
                    return Result.error("Workload endpoint tcp socket URI must not include user info");
                }

                if (StringUtils.isBlank(parsedAddress.getHost())) {
                    return Result.error("Workload endpoint tcp socket URI must include a host");
                }

                if (StringUtils.isNotBlank(parsedAddress.getPath())) {
                    return Result.error("Workload endpoint tcp socket URI must not include a path");
                }

                if (StringUtils.isNotBlank(parsedAddress.getRawQuery())) {
                    return Result.error("Workload endpoint tcp socket URI must not include query values");
                }

                if (StringUtils.isNotBlank(parsedAddress.getFragment())) {
                    return Result.error("Workload endpoint tcp socket URI must not include a fragment");
                }

                String ip = parseIp(parsedAddress.getHost());
                if (ip == null) {
                    return Result.error("Workload endpoint tcp socket URI host component must be an IP:port");
                }

                int port = parsedAddress.getPort();
                if (port == -1) {
                    return Result.error("Workload endpoint tcp socket URI host component must include a port");
                }

                return Result.ok(parsedAddress);
            }
        }

        return Result.error("Workload endpoint socket URI must have a tcp:// or unix:// scheme");
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
