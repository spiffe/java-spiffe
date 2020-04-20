package spiffe.spiffeid;

import lombok.val;
import org.apache.commons.lang3.NotImplementedException;
import spiffe.result.Result;

import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Utility class with methods to read SPIFFE IDs using different mechanisms.
 */
public class SpiffeIdUtils {

    private static final char DEFAULT_CHAR_SEPARATOR = ',';

    /**
     * Reads the Accepted SPIFFE IDs from a System Property and parse them to SpiffeId instances.
     *
     * @param systemProperty name of the System Property that should contain a list of
     * SPIFFE IDs separated by a comma.
     *
     * @return a {@link Result}
     * {@link spiffe.result.Ok} containing a List of SpiffeId instances. If no value is found, returns an empty list.
     * {@link spiffe.result.Error} in case the param systemProperty is blank.
     */
    public static Result<List<SpiffeId>, String> getSpiffeIdsFromSystemProperty(final String systemProperty) {
        if (isBlank(systemProperty)) {
            return Result.error("System property cannot be empty.");
        }

        val spiffeIds = System.getProperty(systemProperty);
        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    /**
     * Read the Accepted SPIFFE IDs from a Security Property (defined in java.security file) and parse
     * them to SpiffeId instances.
     * <p>
     * @param securityProperty name of the Security Property that should contain a list of
     * SPIFFE IDs separated by a comma.
     *
     * @return a Result:
     * {@link spiffe.result.Ok} containing a List of SpiffeId instances. If no value is found, returns an empty list.
     * {@link spiffe.result.Error} in case the param systemProperty is blank.
     */
    public static Result<List<SpiffeId>, String> getSpiffeIdsFromSecurityProperty(final String securityProperty) {
        if (isBlank(securityProperty)) {
            return Result.error("Security property cannot be empty");
        }
        val spiffeIds = Security.getProperty(securityProperty);
        return toListOfSpiffeIds(spiffeIds, DEFAULT_CHAR_SEPARATOR);
    }

    /**
     * Read a file containing a list of SPIFFE IDs and parse them to SpiffeId instances.
     *
     * @param spiffeIdFile
     * @param separator
     * @return
     */
    public static Result<List<SpiffeId>, String> getSpiffeIdListFromFile(final Path spiffeIdFile, final char separator) {
        throw new NotImplementedException("Not implemented");
    }

    /**
     * Parse a string representing a list of SPIFFE IDs and return a Result containing a List of
     * instances of SpiffeId.
     *
     * @param spiffeIds a list of SPIFFE IDs represented in a string
     * @param separator used to separate the SPIFFE IDs in the string.
     * @return a Result containing a List of SpiffeId instances or an Error.
     */
    public static Result<List<SpiffeId>, String> toListOfSpiffeIds(final String spiffeIds, final char separator) {
        if (isBlank(spiffeIds)) {
            return Result.error("SPIFFE IDs is empty");
        }

        val array = spiffeIds.split(String.valueOf(separator));
        val spiffeIdList = Arrays.stream(array)
                .map(SpiffeId::parse)
                .map(Result::getValue)
                .collect(Collectors.toList());

        return Result.ok(spiffeIdList);
    }
}
