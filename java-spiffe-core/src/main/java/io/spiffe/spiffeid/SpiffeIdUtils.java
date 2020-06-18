package io.spiffe.spiffeid;

import lombok.val;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
     * Reads a file containing a list of SPIFFE IDs and parses them to {@link SpiffeId} instances.
     * <p>
     * The file should have one SPIFFE ID per line.
     *
     * @param spiffeIdsFile the path to the file containing a list of SPIFFE IDs
     * @return a List of {@link SpiffeId} parsed from the file provided
     * @throws IOException              if the given spiffeIdsFile cannot be read
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
     * @return a list of {@link SpiffeId} instances.
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

    /**
     * Return the list of the SPIFFE IDs parsed from the String parameter, using the default separator (comma)
     *
     * @param spiffeIds a String representing a list of SPIFFE IDs separeated by comma
     * @return a list of {@link SpiffeId} instances
     * @throws IllegalArgumentException is the string provided is blank
     */
    public static List<SpiffeId> toListOfSpiffeIds(final String spiffeIds) {
        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    private SpiffeIdUtils() {
    }
}
