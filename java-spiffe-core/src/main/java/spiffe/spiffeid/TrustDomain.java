package spiffe.spiffeid;


import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static java.lang.String.format;

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
            throw new IllegalArgumentException("Trust Domain cannot be empty");
        }
        try {
            val uri = new URI(normalize(trustDomain));
            val host = getHost(uri);
            return new TrustDomain(host);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(format("Unable to parse: %s", trustDomain), e);
        }
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

    private static String normalize(String s) {
        return s.toLowerCase().trim();
    }

    private static String getHost(URI uri) {
        if (StringUtils.isBlank(uri.getHost())) {
            return uri.getPath();
        }
        return uri.getHost();
    }
}
