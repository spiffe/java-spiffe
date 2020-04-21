package spiffe.spiffeid;

import lombok.Value;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import spiffe.result.Result;

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

    private static final String SPIFFE_SCHEMA = "spiffe";

    TrustDomain trustDomain;

    String path;

    private SpiffeId(final TrustDomain trustDomain, final String path) {
        this.trustDomain = trustDomain;
        this.path = path;
    }

    /**
     * Returns an instance of a SpiffeId, containing the TrustDomain and
     * a path generated joining the segments (e.g. /path1/path2).
     *
     * @param trustDomain an instance of a TrustDomain
     * @param segments a list of string path segments
     *
     * @return a {@code Resul}, either an {@link spiffe.result.Ok} wrapping a {@link SpiffeId}
     * or an {@link spiffe.result.Error} wrapping the error message.
     */
    public static Result<SpiffeId, String> of(final TrustDomain trustDomain, final String... segments) {
        if (trustDomain == null) {
            return Result.error("Trust Domain cannot be null");
        }

        val path = Arrays.stream(segments)
                .filter(StringUtils::isNotBlank)
                .map(SpiffeId::normalize)
                .map(s -> "/" + s)
                .collect(Collectors.joining());

        return Result.ok(new SpiffeId(trustDomain, path));
    }

    /**
     * Parses a SpiffeId from a string (e.g. spiffe://example.org/test).
     *
     * @param spiffeIdAsString a String representing a spiffeId
     * @return A {@link Result}, either an {@link spiffe.result.Ok} wrapping a {@link SpiffeId}
     * or an {@link spiffe.result.Error} wrapping the error message.
     */
    public static Result<SpiffeId, String> parse(final String spiffeIdAsString) {

        if (StringUtils.isBlank(spiffeIdAsString)) {
            return Result.error("SPIFFE ID cannot be empty");
        }

        try {
            val uri = URI.create(spiffeIdAsString);

            if (!SPIFFE_SCHEMA.equals(uri.getScheme())) {
                return Result.error("Invalid SPIFFE schema");
            }

            val trustDomainResult = TrustDomain.of(uri.getHost());
            if (trustDomainResult.isError()) {
                return Result.error(trustDomainResult.getError());
            }

            val path = uri.getPath();

            return Result.ok(new SpiffeId(trustDomainResult.getValue(), path));

        } catch (IllegalArgumentException e) {
            return Result.error("Could not parse SPIFFE ID %s: %s", spiffeIdAsString, e.getMessage());
        }
    }

    /**
     * Returns true if the trustDomain of the current object equals the
     * trustDomain passed as parameter.
     *
     * @param trustDomain instance of a TrustDomain
     * @return true if the trustDomain given as a parameter is the same as the trustDomain
     * of the current SpiffeId object.
     */
    public boolean memberOf(final TrustDomain trustDomain) {
        return this.trustDomain.equals(trustDomain);
    }

    @Override
    public String toString() {
        return String.format("%s://%s%s", SPIFFE_SCHEMA, this.trustDomain.toString(), this.path);
    }

    private static String normalize(String s) {
        return s.toLowerCase().trim();
    }
}
