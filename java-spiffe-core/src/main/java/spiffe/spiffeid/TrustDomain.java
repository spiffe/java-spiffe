package spiffe.spiffeid;


import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static spiffe.spiffeid.SpiffeId.SPIFFE_SCHEME;

/**
 * A <code>TrustDomain</code> represents a normalized SPIFFE trust domain (e.g. domain.test).
 */
@Value
public class TrustDomain {

    String name;

    private TrustDomain(String trustDomain) {
        this.name = trustDomain;
    }

    /**
     * Creates a trust domain.
     *
     * @param trustDomain a trust domain represented as a string, must not be blank.
     * @return an instance of a {@link TrustDomain}
     *
     * @throws IllegalArgumentException if the given string is blank or cannot be parsed
     */
    public static TrustDomain of(@NonNull String trustDomain) {
        if (StringUtils.isBlank(trustDomain)) {
            throw new IllegalArgumentException("Trust domain cannot be empty");
        }

        URI uri;
        try {
            val normalized = normalize(trustDomain);
            uri = new URI(normalized);
            validateUri(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e.getMessage());
        }

        val host = uri.getHost();
        validateHost(host);
        return new TrustDomain(host);
    }

    private static void validateHost(String host) {
        if (StringUtils.isBlank(host)) {
            throw new IllegalArgumentException("Trust domain cannot be empty");
        }
    }

    private static void validateUri(URI uri) {
        val scheme = uri.getScheme();
        if (StringUtils.isNotBlank(scheme) && !SPIFFE_SCHEME.equals(scheme)) {
            throw new IllegalArgumentException("Invalid scheme");
        }

        val port = uri.getPort();
        if (port != -1) {
            throw new IllegalArgumentException("Port is not allowed");
        }
    }

    private static String normalize(String s) {
        s = s.toLowerCase().trim();
        if (!s.contains("://")) {
            s = SPIFFE_SCHEME.concat("://").concat(s);
        }
        return s;
    }

    /**
     * Returns the trust domain as a string.
     *
     * @return a String with the trust domain
     */
    @Override
    public String toString() {
        return name;
    }
}
