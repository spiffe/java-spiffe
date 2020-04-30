package spiffe.spiffeid;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * A <code>SpiffeId</code> represents a SPIFFE ID as defined in SPIFFE standard.
 * <p>
 * @see <a href="https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md">https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md</a>
 */
@Value
public class SpiffeId {

    public static final String SPIFFE_SCHEME = "spiffe";

    TrustDomain trustDomain;

    String path;

    private SpiffeId(final TrustDomain trustDomain, final String path) {
        this.trustDomain = trustDomain;
        this.path = path;
    }

    /**
     * Returns an instance representing a SPIFFE ID, containing the trust domain and
     * a path generated joining the segments (e.g. /path1/path2).
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @param segments    a list of string path segments
     *
     * @return a {@link SpiffeId}
     */
    public static SpiffeId of(@NonNull final TrustDomain trustDomain, final String... segments) {
        val path = Arrays.stream(segments)
                .filter(StringUtils::isNotBlank)
                .map(SpiffeId::normalize)
                .map(s -> '/' + s)
                .collect(Collectors.joining());
        return new SpiffeId(trustDomain, path);
    }

    /**
     * Parses a SPIFFE ID from a string (e.g. spiffe://example.org/test).
     *
     * @param spiffeIdAsString a String representing a SPIFFE ID
     * @return A {@link SpiffeId}
     * @throws IllegalArgumentException if the given string cannot be parsed
     */
    public static SpiffeId parse(@NonNull final String spiffeIdAsString) {
        if (StringUtils.isBlank(spiffeIdAsString)) {
            throw new IllegalArgumentException("SPIFFE ID cannot be empty");
        }

        val uri = URI.create(spiffeIdAsString);

        if (!SPIFFE_SCHEME.equals(uri.getScheme())) {
            throw new IllegalArgumentException("Invalid SPIFFE schema");
        }

        val trustDomain = TrustDomain.of(uri.getHost());
        val path = uri.getPath();
        return new SpiffeId(trustDomain, path);
    }

    /**
     * Returns true if the trust domain of this SPIFFE ID is the same as the given trust domain.
     *
     * @param trustDomain instance of a {@link TrustDomain}
     * @return <code>true</code> if the given trust domain equals the trust domain of this object, <code>false</code> otherwise
     */
    public boolean memberOf(final TrustDomain trustDomain) {
        return this.trustDomain.equals(trustDomain);
    }

    @Override
    public String toString() {
        return String.format("%s://%s%s", SPIFFE_SCHEME, this.trustDomain.toString(), this.path);
    }

    private static String normalize(String s) {
        return s.toLowerCase().trim();
    }
}
