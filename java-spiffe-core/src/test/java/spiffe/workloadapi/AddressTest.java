package spiffe.workloadapi;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.exception.SocketEndpointAddressException;

import java.net.URI;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AddressTest {

    @ParameterizedTest
    @MethodSource("provideTestAddress")
    void parseAddressInvalid(String input, Object expected) {
        URI result = null;
        try {
            result = Address.parseAddress(input);
            assertEquals(expected, result);
        } catch (SocketEndpointAddressException e) {
            assertEquals(expected, e.getMessage());
        }
    }

    static Stream<Arguments> provideTestAddress() {
        return Stream.of(
                Arguments.of("unix://foo", URI.create("unix://foo")),
                Arguments.of("\\t", "Workload endpoint socket is not a valid URI: \\t"),
                Arguments.of("blah", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: blah"),
                Arguments.of("unix:opaque", "Workload endpoint unix socket URI must not be opaque: unix:opaque"),
                Arguments.of("unix://", "Workload endpoint socket is not a valid URI: unix://"),
                Arguments.of("unix://foo?whatever", "Workload endpoint unix socket URI must not include query values: unix://foo?whatever"),
                Arguments.of("unix://foo#whatever", "Workload endpoint unix socket URI must not include a fragment: unix://foo#whatever"),
                Arguments.of("unix://john:doe@foo/path", "Workload endpoint unix socket URI must not include user info: unix://john:doe@foo/path"),

                Arguments.of("tcp://1.2.3.4:5", URI.create("tcp://1.2.3.4:5")),
                Arguments.of("tcp:opaque", "Workload endpoint tcp socket URI must not be opaque: tcp:opaque"),
                Arguments.of("tcp://", "Workload endpoint socket is not a valid URI: tcp://"),
                Arguments.of("tcp://1.2.3.4:5?whatever", "Workload endpoint tcp socket URI must not include query values: tcp://1.2.3.4:5?whatever"),
                Arguments.of("tcp://1.2.3.4:5#whatever", "Workload endpoint tcp socket URI must not include a fragment: tcp://1.2.3.4:5#whatever"),
                Arguments.of("tcp://john:doe@1.2.3.4:5/path", "Workload endpoint tcp socket URI must not include user info: tcp://john:doe@1.2.3.4:5/path"),
                Arguments.of("tcp://1.2.3.4:5/path", "Workload endpoint tcp socket URI must not include a path: tcp://1.2.3.4:5/path"),
                Arguments.of("tcp://foo", "Workload endpoint tcp socket URI host component must be an IP:port: tcp://foo"),
                Arguments.of("tcp://1.2.3.4", "Workload endpoint tcp socket URI host component must include a port: tcp://1.2.3.4"),

                Arguments.of("blah://foo", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: blah://foo")
        );
    }
}