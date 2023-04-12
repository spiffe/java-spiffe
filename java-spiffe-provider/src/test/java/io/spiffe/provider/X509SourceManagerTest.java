package io.spiffe.provider;

import io.spiffe.utils.TestUtils;
import io.spiffe.workloadapi.Address;
import io.spiffe.workloadapi.X509Source;
import org.junit.jupiter.api.Test;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;

class X509SourceManagerTest {

    @Test
    void getX509Source_returnTheX509SourceInstance() throws Exception {
        Field field = X509SourceManager.class.getDeclaredField("x509Source");
        field.setAccessible(true);
        X509Source source = new X509SourceStub();
        field.set(null, source);

        X509Source x509Source = X509SourceManager.getX509Source();
        assertEquals(source, x509Source);
    }

    @Test
    void getX509Source_defaultAddressNotSet() throws Exception {
        new EnvironmentVariables(Address.SOCKET_ENV_VARIABLE, "").execute(() -> {
            try {
                X509SourceManager.getX509Source();
            } catch (IllegalStateException e) {
                assertEquals("Endpoint Socket Address Environment Variable is not set: SPIFFE_ENDPOINT_SOCKET", e.getMessage());
            }
        });
    }
}