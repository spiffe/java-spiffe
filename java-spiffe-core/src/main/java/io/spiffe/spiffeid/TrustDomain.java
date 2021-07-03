package io.spiffe.spiffeid;


import io.spiffe.exception.InvalidSpiffeIdException;
import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;

import static io.spiffe.spiffeid.SpiffeId.BAD_TRUST_DOMAIN_CHAR;

/**
 * Represents the name of a SPIFFE trust domain (e.g. 'domain.test').
 */
@Value
public class TrustDomain {

    String name;

    TrustDomain(final String trustDomain) {
        this.name = trustDomain;
    }

    /**
     * Creates a trust domain.
     *
     * @param idOrName the name of a Trust Domain or a string representing a SpiffeId.
     *
     * @return an instance of a {@link TrustDomain}
     * @throws IllegalArgumentException if the given string is empty.
     * @throws InvalidSpiffeIdException if the given string contains an invalid char.
     */
    public static TrustDomain parse(@NonNull final String idOrName) {

        if (StringUtils.isBlank(idOrName)) {
            throw new IllegalArgumentException("Trust domain is missing");
        }

        // Something looks kinda like a scheme separator, let's try to parse as
        // an ID. We use :/ instead of :// since the diagnostics are better for
        // a bad input like spiffe:/trustdomain.
        if (idOrName.contains(":/")) {
            SpiffeId spiffeId = SpiffeId.parse(idOrName);
            return spiffeId.getTrustDomain();
        }

        validateTrustDomainName(idOrName);
        return new TrustDomain(idOrName);
    }

    /**
     * Creates a SPIFFE ID from this trust domain and the given path segments.
     *
     * @param segments path segments
     * @return a {@link SpiffeId} with the current trust domain and the given path segments
     * @throws InvalidSpiffeIdException if the given path segments contain invalid chars or empty or dot segments
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
        return SpiffeId.SPIFFE_SCHEME + "://" + name;
    }

    static void validateTrustDomainName(final String name) {
        for (char c : name.toCharArray()) {
            if (!isValidTrustDomainChar(c)) {
                throw new InvalidSpiffeIdException(BAD_TRUST_DOMAIN_CHAR);
            }
        }
    }

    static boolean isValidTrustDomainChar(char c) {
        if (c >= 'a' && c <= 'z') {
            return true;
        }

        if (c >= '0' && c <= '9') {
            return true;
        }

        return c == '-' || c == '.' || c == '_';
    }
}
