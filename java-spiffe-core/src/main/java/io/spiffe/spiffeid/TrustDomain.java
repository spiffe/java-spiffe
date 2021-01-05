package io.spiffe.spiffeid;


import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Represents the name of a SPIFFE trust domain (e.g. 'domain.test').
 */
@Value
public class TrustDomain {

    public static final int TRUST_DOMAIN_MAXIMUM_LENGTH = 255;

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

    /**
     * Returns the trust domain as SPIFFE ID string (e.g. 'spiffe://example.org')
     *
     * @return a String formatted as a SPIFFE ID
     */
    public String toIdString() {
        return String.format("%s://%s", SpiffeId.SPIFFE_SCHEME, name);
    }

    private static void validateHost(final String host) {
        if (StringUtils.isBlank(host)) {
            throw new IllegalArgumentException("Trust domain cannot be empty");
        }

        if (host.length() > TRUST_DOMAIN_MAXIMUM_LENGTH) {
            throw new IllegalArgumentException(String.format("Trust domain maximum length is %s bytes", TRUST_DOMAIN_MAXIMUM_LENGTH));
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

    private static String normalize(final String s) {
        String result = s.toLowerCase().trim();
        if (!result.contains("://")) {
            result = SpiffeId.SPIFFE_SCHEME.concat("://").concat(result);
        }
        return result;
    }
}
