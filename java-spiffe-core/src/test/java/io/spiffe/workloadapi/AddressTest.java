package io.spiffe.workloadapi;

import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class AddressTest {

    @ParameterizedTest
    @MethodSource("provideTestAddress")
    void parseAddress(String input, Object expected) {
        URI result = null;
        try {
            result = Address.parseAddress(input);
            assertEquals(expected, result);
        } catch (SocketEndpointAddressException e) {
            assertEquals(expected, e.getMessage());
        }
    }

    @Test
    void parseAddress_nullArgument() {
        try {
            Address.parseAddress(null);
        } catch (NullPointerException e) {
            assertEquals("address is marked non-null but is null", e.getMessage());
        } catch (SocketEndpointAddressException e) {
            fail();
        }
    }

    static Stream<Arguments> provideTestAddress() {
        return Stream.of(
                Arguments.of("", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: "),
                Arguments.of("unix:///foo", URI.create("unix:///foo")),
                Arguments.of("unix:/path/to/endpoint.sock", URI.create("unix:/path/to/endpoint.sock")),
                Arguments.of("unix:///path/to/endpoint.sock", URI.create("unix:///path/to/endpoint.sock")),
                Arguments.of("tcp://127.0.0.1:8000", URI.create("tcp://127.0.0.1:8000")),

                Arguments.of("", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: "),
                Arguments.of("\\t", "Workload endpoint socket is not a valid URI: \\t"),
                Arguments.of("///foo", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: ///foo"),
                Arguments.of("blah", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: blah"),
                Arguments.of("blah:///foo", "Workload endpoint socket URI must have a tcp:// or unix:// scheme: blah:///foo"),

                Arguments.of("unix:opaque", "Workload endpoint unix socket URI must not be opaque: unix:opaque"),
                Arguments.of("unix:/", "Workload endpoint unix socket path cannot be blank: unix:/"),
                Arguments.of("unix://", "Workload endpoint socket is not a valid URI: unix://"),
                Arguments.of("unix:///", "Workload endpoint unix socket path cannot be blank: unix:///"),
                Arguments.of("unix://foo", "Workload endpoint unix socket URI must not include authority component: unix://foo"),
                Arguments.of("unix:///foo?whatever", "Workload endpoint unix socket URI must not include query values: unix:///foo?whatever"),
                Arguments.of("unix:///foo#whatever", "Workload endpoint unix socket URI must not include a fragment: unix:///foo#whatever"),

                Arguments.of("tcp://127.0.0.1:8000/foo", "Workload endpoint tcp socket URI must not include a path: tcp://127.0.0.1:8000/foo"),
                Arguments.of("tcp:opaque", "Workload endpoint tcp socket URI must not be opaque: tcp:opaque"),
                Arguments.of("tcp://", "Workload endpoint socket is not a valid URI: tcp://"),
                Arguments.of("tcp:///test", "Workload endpoint tcp socket URI must include a host: tcp:///test"),
                Arguments.of("tcp://1.2.3.4:5?whatever", "Workload endpoint tcp socket URI must not include query values: tcp://1.2.3.4:5?whatever"),
                Arguments.of("tcp://1.2.3.4:5#whatever", "Workload endpoint tcp socket URI must not include a fragment: tcp://1.2.3.4:5#whatever"),
                Arguments.of("tcp://john:doe@1.2.3.4:5/path", "Workload endpoint tcp socket URI must not include user info: tcp://john:doe@1.2.3.4:5/path"),
                Arguments.of("tcp://foo:9000", "Workload endpoint tcp socket URI host component must be an IP:port: tcp://foo:9000"),
                Arguments.of("tcp://1.2.3.4", "Workload endpoint tcp socket URI host component must include a port: tcp://1.2.3.4")
        );
    }

    @Test
    void getDefaultAddress() throws Exception {
        TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "unix:/tmp/agent.sock" );
        String defaultAddress = Address.getDefaultAddress();
        assertEquals("unix:/tmp/agent.sock", defaultAddress);
    }

    @Test
    void getDefaultAddress_isBlankThrowsException() throws Exception {
        TestUtils.setEnvironmentVariable(Address.SOCKET_ENV_VARIABLE, "");
        String defaultAddress = null;
        try {
            Address.getDefaultAddress();
            fail();
        } catch (Exception e) {
            assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
        }
    }
}