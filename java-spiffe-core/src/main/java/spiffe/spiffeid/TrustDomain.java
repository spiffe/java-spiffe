package spiffe.spiffeid;


import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import spiffe.result.Result;

import java.net.URI;
import java.net.URISyntaxException;

import static java.lang.String.format;

/**
 * A <code>TrustDomain</code> represents a normalized SPIFFE trust domain (e.g. domain.test).
 */
@Value
public class TrustDomain {

    String trustDomain;

    private TrustDomain(String trustDomain) {
        this.trustDomain = trustDomain;
    }

    /**
     * Creates an instance of a TrustDomain.
     *
     * @param trustDomain a TrustDomain represented as a String, must not be blank.
     * @return an Ok result containing the parsed TrustDomain, or an Error if the trustDomain cannot be parsed
     */
    public static Result<TrustDomain, String> of(String trustDomain) {
        if (StringUtils.isBlank(trustDomain)) {
            return Result.error("Trust Domain cannot be empty.");
        }
        try {
            val uri = new URI(normalize(trustDomain));
            val result = new TrustDomain(getHost(uri));
            return Result.ok(result);
        } catch (URISyntaxException e) {
            return Result.error(format("Unable to parse: %s.", trustDomain));
        }
    }

    /**
     * Returns the trustDomain as String
     * @return a String with the Trust Domain
     */
    @Override
    public String toString() {
        return trustDomain;
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
