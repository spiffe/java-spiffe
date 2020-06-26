package io.spiffe.spiffeid;

import lombok.val;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Utility class with methods to read SPIFFE IDs using different mechanisms.
 */
public final class SpiffeIdUtils {

    private static final char DEFAULT_CHAR_SEPARATOR = ',';

    private SpiffeIdUtils() {
    }

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
    public static Set<SpiffeId> getSpiffeIdSetFromFile(final Path spiffeIdsFile) throws IOException {
        try (val lines = Files.lines(spiffeIdsFile)) {
            return lines
                    .map(SpiffeId::parse)
                    .collect(Collectors.toSet());
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
    public static Set<SpiffeId> toSetOfSpiffeIds(final String spiffeIds, final char separator) {
        if (isBlank(spiffeIds)) {
            return Collections.emptySet();
        }

        val array = spiffeIds.split(String.valueOf(separator));
        return Arrays.stream(array)
                .map(SpiffeId::parse)
                .collect(Collectors.toSet());
    }

    /**
     * Return the list of the SPIFFE IDs parsed from the String parameter, using the default separator (comma)
     *
     * @param spiffeIds a String representing a list of SPIFFE IDs separated by comma
     * @return a list of {@link SpiffeId} instances
     * @throws IllegalArgumentException is the string provided is blank
     */
    public static Set<SpiffeId> toSetOfSpiffeIds(final String spiffeIds) {
        return toSetOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }
}
