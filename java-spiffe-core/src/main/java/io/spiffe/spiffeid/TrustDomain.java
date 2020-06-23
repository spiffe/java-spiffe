package io.spiffe.spiffeid;


import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Represents a normalized SPIFFE trust domain (e.g. 'domain.test').
 */
@Value
public class TrustDomain {

    String name;

    private TrustDomain(final String trustDomain) {
        this.name = trustDomain;
    }

    /**
     * Creates a trust domain.
     *
     * @param trustDomain a trust domain represented as a string, must not be blank.
     * @return an instance of a {@link TrustDomain}
     * @throws IllegalArgumentException if the given string is blank or cannot be parsed
     */
    public static TrustDomain of(@NonNull final String trustDomain) {
        if (StringUtils.isBlank(trustDomain)) {
            throw new IllegalArgumentException("Trust domain cannot be empty");
        }

        URI uri;
        try {
            val normalized = normalize(trustDomain);
            uri = new URI(normalized);
            validateUri(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }

        val host = uri.getHost();
        validateHost(host);
        return new TrustDomain(host);
    }

    /**
     * Creates a SPIFFE ID from this trust domain and the given path segments.
     *
     * @param segments path segments
     * @return a {@link SpiffeId} with the current trust domain and the given path segments
     */
    public SpiffeId newSpiffeId(final String... segments) {
        return SpiffeId.of(this, segments);
    }

    /**
     * Returns the trust domain as a String.
     *
     * @return a String with the trust domain
     */
    @Override
    public String toString() {
        return name;
    }

    private static void validateHost(final String host) {
        if (StringUtils.isBlank(host)) {
            throw new IllegalArgumentException("Trust domain cannot be empty");
        }
    }

    private static void validateUri(final URI uri) {
        val scheme = uri.getScheme();
        if (!SpiffeId.SPIFFE_SCHEME.equals(scheme)) {
            throw new IllegalArgumentException("Invalid scheme");
        }

        val port = uri.getPort();
        if (port != -1) {
            throw new IllegalArgumentException("Trust Domain: port is not allowed");
        }
    }

    private static String normalize(String s) {
        String result = s.toLowerCase().trim();
        if (!result.contains("://")) {
            result = SpiffeId.SPIFFE_SCHEME.concat("://").concat(result);
        }
        return result;
    }
}
