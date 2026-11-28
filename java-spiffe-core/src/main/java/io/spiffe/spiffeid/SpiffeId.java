package io.spiffe.spiffeid;

import io.spiffe.exception.InvalidSpiffeIdException;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;

import static io.spiffe.spiffeid.TrustDomain.isValidTrustDomainChar;
import static io.spiffe.spiffeid.TrustDomain.toLowerAscii;

/**
 * Represents a SPIFFE ID as defined in the SPIFFE standard.
 * <p>
 * @see <a href="https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md">https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md</a>
 */
public final class SpiffeId {

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
    static final String MISSING_LEADING_SLASH = "Path must start with '/'";

    private final TrustDomain trustDomain;

    private final String path;

    private SpiffeId(TrustDomain trustDomain, String path) {
        this.trustDomain = Objects.requireNonNull(trustDomain, "trustDomain must not be null");
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
    public static SpiffeId fromSegments(TrustDomain trustDomain, String... segments) {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        return new SpiffeId(trustDomain, joinPathSegments(segments));
    }

    /**
     * Returns a new SPIFFE ID in the given trust domain with the given path (e.g. '/ns/default/sa/backend').
     * The path must be a valid absolute path according to the SPIFFE specification. An empty path
     * returns the SPIFFE ID of the trust domain, which has no path (e.g. 'spiffe://example.org').
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param trustDomain an instance of a {@link TrustDomain}
     * @param path        the path of the SPIFFE ID
     * @return a {@link SpiffeId}
     * @throws NullPointerException     if the trust domain or the path is null
     * @throws InvalidSpiffeIdException if the path doesn't start with '/', has a trailing slash, contains an invalid
     *                                  char or an empty or dot segment
     */
    public static SpiffeId fromPath(TrustDomain trustDomain, String path) {
        Objects.requireNonNull(trustDomain, "trustDomain must not be null");
        Objects.requireNonNull(path, "path must not be null");
        if (!path.isEmpty()) {
            validatePath(path);
        }
        return new SpiffeId(trustDomain, path);
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

        int schemeSeparatorIndex = id.indexOf("://");
        if (schemeSeparatorIndex <= 0) {
            throw new InvalidSpiffeIdException(WRONG_SCHEME);
        }

        String scheme = id.substring(0, schemeSeparatorIndex);
        if (!SPIFFE_SCHEME.equalsIgnoreCase(scheme)) {
            throw new InvalidSpiffeIdException(WRONG_SCHEME);
        }

        String rest = id.substring(schemeSeparatorIndex + 3);

        int i = 0;
        for (char c : rest.toCharArray()) {
            if (c == '/') {
                break;
            }
            char normalized = toLowerAscii(c);
            if (!isValidTrustDomainChar(normalized)) {
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

        String normalizedTrustDomain = toLowerAscii(td);
        return new SpiffeId(new TrustDomain(normalizedTrustDomain), path);
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
     * Returns a new SPIFFE ID in the same trust domain, with the given path appended to the path of this SPIFFE ID
     * (e.g. appending '/api' to 'spiffe://example.org/backend' returns 'spiffe://example.org/backend/api').
     * The path to append must be a valid absolute path according to the SPIFFE specification. Appending an
     * empty path returns this SPIFFE ID.
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param path the path to append
     * @return a {@link SpiffeId} with the appended path
     * @throws NullPointerException     if the path is null
     * @throws InvalidSpiffeIdException if the path doesn't start with '/', has a trailing slash, contains an invalid
     *                                  char or an empty or dot segment
     */
    public SpiffeId appendPath(final String path) {
        Objects.requireNonNull(path, "path must not be null");
        if (path.isEmpty()) {
            return this;
        }
        validatePath(path);
        return new SpiffeId(this.trustDomain, this.path + path);
    }

    /**
     * Returns a new SPIFFE ID in the same trust domain, with the given path segments appended to the path of this
     * SPIFFE ID (e.g. appending 'api' and 'v1' to 'spiffe://example.org/backend' returns
     * 'spiffe://example.org/backend/api/v1'). The path segments must be valid according to the SPIFFE
     * specification and must not contain path separators.
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param segments the path segments to append
     * @return a {@link SpiffeId} with the appended path segments
     * @throws NullPointerException     if the segments array is null
     * @throws InvalidSpiffeIdException if a given path segment contains an invalid char or empty or dot segment
     */
    public SpiffeId appendSegments(final String... segments) {
        return new SpiffeId(this.trustDomain, this.path + joinPathSegments(segments));
    }

    /**
     * Returns a new SPIFFE ID in the same trust domain with the given path, replacing the path of this SPIFFE ID.
     * The path must be a valid absolute path according to the SPIFFE specification. An empty path returns
     * the SPIFFE ID of the trust domain.
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param path the new path
     * @return a {@link SpiffeId} in the same trust domain with the given path
     * @throws NullPointerException     if the path is null
     * @throws InvalidSpiffeIdException if the path doesn't start with '/', has a trailing slash, contains an invalid
     *                                  char or an empty or dot segment
     * @see #fromPath(TrustDomain, String)
     */
    public SpiffeId replacePath(final String path) {
        return fromPath(this.trustDomain, path);
    }

    /**
     * Returns a new SPIFFE ID in the same trust domain with the given joined path segments, replacing the path of this
     * SPIFFE ID. The path segments must be valid according to the SPIFFE specification and must not contain path
     * separators.
     * See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
     *
     * @param segments the path segments of the new path
     * @return a {@link SpiffeId} in the same trust domain with the given path segments
     * @throws NullPointerException     if the segments array is null
     * @throws InvalidSpiffeIdException if a given path segment contains an invalid char or empty or dot segment
     * @see #fromSegments(TrustDomain, String...)
     */
    public SpiffeId replaceSegments(final String... segments) {
        return fromSegments(this.trustDomain, segments);
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
            throw new InvalidSpiffeIdException(EMPTY);
        }

        if (!path.startsWith("/")) {
            throw new InvalidSpiffeIdException(MISSING_LEADING_SLASH);
        }

        // Keep trailing empty segments so "/a/" is distinguished from "/a"
        String[] segments = path.substring(1).split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            boolean lastSegment = i == segments.length - 1;

            if (segment.isEmpty()) {
                throw new InvalidSpiffeIdException(lastSegment ? TRAILING_SLASH : EMPTY_SEGMENT);
            }

            validatePathSegment(segment);
        }
    }

    private static String joinPathSegments(final String... segments) {
        Objects.requireNonNull(segments, "segments must not be null");

        StringBuilder path = new StringBuilder();
        for (String segment : segments) {
            validatePathSegment(segment);
            path.append('/');
            path.append(segment);
        }
        return path.toString();
    }

    private static void validatePathSegment(String segment) {
        if (StringUtils.isEmpty(segment)) {
            throw new InvalidSpiffeIdException(EMPTY);
        }

        if (".".equals(segment) || "..".equals(segment)) {
            throw new InvalidSpiffeIdException(DOT_SEGMENT);
        }

        for (char c : segment.toCharArray()) {
            if (!isValidPathSegmentChar(c)) {
                throw new InvalidSpiffeIdException(BAD_PATH_SEGMENT_CHAR);
            }
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

    public TrustDomain getTrustDomain() {
        return trustDomain;
    }

    public String getPath() {
        return path;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SpiffeId)) return false;
        SpiffeId spiffeId = (SpiffeId) o;
        return Objects.equals(trustDomain, spiffeId.trustDomain) &&
                Objects.equals(path, spiffeId.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustDomain, path);
    }
}
