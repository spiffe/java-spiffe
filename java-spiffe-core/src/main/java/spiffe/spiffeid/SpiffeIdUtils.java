package spiffe.spiffeid;

import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.EMPTY_LIST;
import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Utility class with methods to read SPIFFE IDs using different mechanisms.
 */
public class SpiffeIdUtils {

    private static final char DEFAULT_CHAR_SEPARATOR = ',';

    /**
     * Reads the Accepted SPIFFE IDs from a system property and parses them to {@link SpiffeId} instances.
     *
     * @param systemProperty name of the system property that contains a list of SPIFFE IDs separated by a commas.
     * @return a list of {@link SpiffeId} parsed from the values read from the security property, in case there's no values
     * in the System property, it returns an emtpy list
     *
     * @throws IllegalArgumentException if the given system property is empty or if any of the SPIFFE IDs
     * cannot be parsed
     */
    public static List<SpiffeId> getSpiffeIdsFromSystemProperty(final String systemProperty) {
        if (isBlank(systemProperty)) {
            throw new IllegalArgumentException("Argument systemProperty cannot be empty");
        }

        val spiffeIds = System.getProperty(systemProperty);
        if (StringUtils.isBlank(spiffeIds)) {
            return EMPTY_LIST;
        }
        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    /**
     * Reads the accepted SPIFFE IDs from a security Property (defined in java.security file) and parses
     * them to {@link SpiffeId} instances.
     *
     * @param securityProperty name of the security property that contains a list of SPIFFE IDs separated by commas.
     * @return a List of {@link SpiffeId} parsed from the values read from the given security property
     *
     * @throws IllegalArgumentException if the security property is empty or if any of the SPIFFE IDs
     * cannot be parsed
     */
    public static List<SpiffeId> getSpiffeIdsFromSecurityProperty(final String securityProperty) {
        if (isBlank(securityProperty)) {
            throw new IllegalArgumentException("Argument securityProperty cannot be empty");
        }

        val spiffeIds = Security.getProperty(securityProperty);
        if (StringUtils.isBlank(spiffeIds)) {
            return EMPTY_LIST;
        }

        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    /**
     * Reads a file containing a list of SPIFFE IDs and parses them to {@link SpiffeId} instances.
     * <p>
     * The file should have one SPIFFE ID per line.
     *
     * @param spiffeIdsFile the path to the file containing a list of SPIFFE IDs
     * @return a List of {@link SpiffeId} parsed from the file provided
     *
     * @throws IOException if the given spiffeIdsFile cannot be read
     * @throws IllegalArgumentException if any of the SPIFFE IDs in the file cannot be parsed
     */
    public static List<SpiffeId> getSpiffeIdListFromFile(final Path spiffeIdsFile) throws IOException {
        try (Stream<String> lines = Files.lines(spiffeIdsFile)) {
            return lines
                    .map(SpiffeId::parse)
                    .collect(Collectors.toList());
        }
    }

    /**
     * Parses a string representing a list of SPIFFE IDs and returns a list of
     * instances of {@link SpiffeId}.
     *
     * @param spiffeIds a list of SPIFFE IDs represented in a string
     * @param separator used to separate the SPIFFE IDs in the string.
     *
     * @return a list of {@link SpiffeId} instances.
     *
     * @throws IllegalArgumentException is the string provided is blank
     */
    public static List<SpiffeId> toListOfSpiffeIds(final String spiffeIds, final char separator) {
        if (isBlank(spiffeIds)) {
            return EMPTY_LIST;
        }

        val array = spiffeIds.split(String.valueOf(separator));
        return Arrays.stream(array)
                .map(SpiffeId::parse)
                .collect(Collectors.toList());
    }

    public static List<SpiffeId> toListOfSpiffeIds(final String spiffeIds) {
        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    private SpiffeIdUtils() {}
}
