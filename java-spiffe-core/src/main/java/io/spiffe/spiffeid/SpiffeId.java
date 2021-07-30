package io.spiffe.spiffeid;

import io.spiffe.exception.InvalidSpiffeIdException;
import lombok.NonNull;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;

import static io.spiffe.spiffeid.TrustDomain.isValidTrustDomainChar;

/**
 * Represents a SPIFFE ID as defined in the SPIFFE standard.
 * <p>
 * @see <a href="https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md">https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md</a>
 */
@Value
public class SpiffeId {

    static final String SPIFFE_SCHEME = "spiffe";
    static final String SCHEME_PREFIX = SPIFFE_SCHEME + "://";

    static final String EMPTY = "Cannot be empty";
    static final String MISSING_TRUST_DOMAIN = "Trust domain is missing";
    static final String WRONG_SCHEME = "Scheme is missing or invalid";
    static final String BAD_TRUST_DOMAIN_CHAR = "Trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores";
    static final String BAD_PATH_SEGMENT_CHAR = "Path segment characters are limited to letters, numbers, dots, dashes, and underscores";
    static final String DOT_SEGMENT = "Path cannot contain dot segments";
    static final String EMPTY_SEGMENT = "Path cannot contain empty segments";
    static final String TRAILING_SLASH = "Path cannot have a trailing slash";


    TrustDomain trustDomain;

    String path;

    private SpiffeId(final TrustDomain trustDomain, final String path) {
        this.trustDomain = trustDomain;
        this.path = path;
    }


    /**
     * Returns a new SPIFFE ID in the given trust domain with joined
     * path segments. The path segments must be valid according to the SPIFFE
     * specification and must not contain path separators.
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @param segments    a list of string path segments
     * @return a {@link SpiffeId}
     * @throws InvalidSpiffeIdException if a given path segment contains an invalid char or empty or dot segment
     */
    public static SpiffeId fromSegments(@NonNull final TrustDomain trustDomain, final String... segments) {
        StringBuilder path = new StringBuilder();
        for (String p : segments) {
            validatePath(p);
            path.append('/');
            path.append(p);
        }

        return new SpiffeId(trustDomain, path.toString());
    }

    /**
     * Parses a SPIFFE ID from a string (e.g. spiffe://example.org/test).
     *
     * @param id a String representing a SPIFFE ID
     * @return A {@link SpiffeId}
     * @throws IllegalArgumentException if the given string is empty
     * @throws InvalidSpiffeIdException if the given string id contain an invalid scheme, invalid char or empty or dot segment
     */
    public static SpiffeId parse(final String id) {
        if (StringUtils.isBlank(id)) {
            throw new IllegalArgumentException(EMPTY);
        }

        if (!id.contains(SCHEME_PREFIX)) {
            throw new InvalidSpiffeIdException(WRONG_SCHEME);
        }

        String rest = id.substring(SCHEME_PREFIX.length());

        int i = 0;
        for (char c : rest.toCharArray()) {
            if (c == '/'){
                break;
            }
            if (!isValidTrustDomainChar(c)) {
                throw new InvalidSpiffeIdException(BAD_TRUST_DOMAIN_CHAR);
            }
            i++;
        }

        if (i == 0) {
            throw new InvalidSpiffeIdException(MISSING_TRUST_DOMAIN);
        }

        String td = rest.substring(0, i);
        String path = rest.substring(i);

        if (StringUtils.isNotBlank(path)) {
            validatePath(path);
        }

        return new SpiffeId(new TrustDomain(td), path);
    }

    /**
     * Returns true if the trust domain of this SPIFFE ID is the same as trust domain given as parameter.
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @return <code>true</code> if the given trust domain equals the trust domain of this object,
     * <code>false</code> otherwise
     */
    public boolean memberOf(final TrustDomain trustDomain) {
        return this.trustDomain.equals(trustDomain);
    }

    /**
     * Returns the string representation of the SPIFFE ID, concatenating schema, trust domain,
     * and path segments (e.g. 'spiffe://example.org/path1/path2')
     */
    @Override
    public String toString() {
        return String.format("%s://%s%s", SPIFFE_SCHEME, this.trustDomain.toString(), this.path);
    }

    /**
     *  Validates that a path string is a conformant path for a SPIFFE ID.
     *  See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     */
    public static void validatePath(String path) {
        if (StringUtils.isBlank(path)) {
            throw new IllegalArgumentException(EMPTY);
        }

        int segmentStart = 0;
        int segmentEnd = 0;

        for ( ; segmentEnd < path.length(); segmentEnd++) {
            char c = path.charAt(segmentEnd);
            if (c == '/') {
                switch (path.substring(segmentStart, segmentEnd)) {
                    case "/":
                        throw new InvalidSpiffeIdException(EMPTY_SEGMENT);
                    case "/.":
                    case "/..":
                        throw new InvalidSpiffeIdException(DOT_SEGMENT);
                }
                segmentStart = segmentEnd;
                continue;
            }
            if (!isValidPathSegmentChar(c)) {
                throw new InvalidSpiffeIdException(BAD_PATH_SEGMENT_CHAR);
            }
        }

        switch (path.substring(segmentStart, segmentEnd)) {
            case "/":
                throw new InvalidSpiffeIdException(TRAILING_SLASH);
            case "/.":
            case "/..":
                throw new InvalidSpiffeIdException(DOT_SEGMENT);
        }
    }

    private static boolean isValidPathSegmentChar(char c) {
        if (c >= 'a' && c <= 'z')
            return true;
        if (c >= 'A' && c <= 'Z')
            return true;
        if (c >= '0' && c <= '9')
            return true;
        return c == '-' || c == '.' || c == '_';
    }
}
