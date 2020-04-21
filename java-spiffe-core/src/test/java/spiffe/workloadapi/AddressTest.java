package spiffe.workloadapi;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.result.Result;

import java.net.URI;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AddressTest {

    @ParameterizedTest
    @MethodSource("provideTestAddress")
    void parseAddressInvalid(String input, Result expected) {
        Result<URI, String> result = Address.parseAddress(input);
        assertEquals(expected, result);
    }

    static Stream<Arguments> provideTestAddress() {
        return Stream.of(
                Arguments.of("unix://foo", Result.ok(URI.create("unix://foo"))),
                Arguments.of("\\t", Result.error("Workload endpoint socket is not a valid URI: Illegal character in path at index 0: \\t")),
                Arguments.of("blah", Result.error("Workload endpoint socket URI must have a tcp:// or unix:// scheme")),
                Arguments.of("unix:opaque", Result.error("Workload endpoint unix socket URI must not be opaque")),
                Arguments.of("unix://", Result.error("Workload endpoint socket is not a valid URI: Expected authority at index 7: unix://")),
                Arguments.of("unix://foo?whatever", Result.error("Workload endpoint unix socket URI must not include query values")),
                Arguments.of("unix://foo#whatever", Result.error("Workload endpoint unix socket URI must not include a fragment")),
                Arguments.of("unix://john:doe@foo/path", Result.error("Workload endpoint unix socket URI must not include user info")),

                Arguments.of("tcp://1.2.3.4:5", Result.ok(URI.create("tcp://1.2.3.4:5"))),
                Arguments.of("tcp:opaque", Result.error("Workload endpoint tcp socket URI must not be opaque")),
                Arguments.of("tcp://", Result.error("Workload endpoint socket is not a valid URI: Expected authority at index 6: tcp://")),
                Arguments.of("tcp://1.2.3.4:5?whatever", Result.error("Workload endpoint tcp socket URI must not include query values")),
                Arguments.of("tcp://1.2.3.4:5#whatever", Result.error("Workload endpoint tcp socket URI must not include a fragment")),
                Arguments.of("tcp://john:doe@1.2.3.4:5/path", Result.error("Workload endpoint tcp socket URI must not include user info")),
                Arguments.of("tcp://1.2.3.4:5/path", Result.error("Workload endpoint tcp socket URI must not include a path")),
                Arguments.of("tcp://foo", Result.error("Workload endpoint tcp socket URI host component must be an IP:port")),
                Arguments.of("tcp://1.2.3.4", Result.error("Workload endpoint tcp socket URI host component must include a port")),

                Arguments.of("blah://foo", Result.error("Workload endpoint socket URI must have a tcp:// or unix:// scheme"))
        );
    }
}