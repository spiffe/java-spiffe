package io.spiffe.provider;

import io.spiffe.workloadapi.X509Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeSslContextFactoryTest {

    X509Source x509Source;

    @BeforeEach
    void setup() {
        x509Source = new X509SourceStub();
    }

    @Test
    void getSslContext_withX509Source() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withSupplierOfSpiffeIds() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptedSpiffeIdsSupplier(Collections::emptySet)
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withAcceptAny() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_withOtherSslProtocol() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .acceptAnySpiffeId()
                        .sslProtocol("TLSv1.1")
                        .build();
        try {
            assertNotNull(SpiffeSslContextFactory.getSslContext(options));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        }
    }

    @Test
    void getSslContext_nullOptions() throws KeyManagementException, NoSuchAlgorithmException {
        try {
            SpiffeSslContextFactory.getSslContext(null);
        } catch (NullPointerException e) {
            assertEquals("options must not be null", e.getMessage());
        }
    }

    @Test
    void getSslContext_nullX509Source() throws KeyManagementException, NoSuchAlgorithmException {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .acceptAnySpiffeId()
                        .build();
        try {
            SpiffeSslContextFactory.getSslContext(options);
        } catch (IllegalArgumentException e) {
            assertEquals("x509Source option must not be null, an X.509 Source must be provided", e.getMessage());
        }
    }

    @Test
    void getSslContext_noSupplierAndAcceptAnyNotSet() {
        SpiffeSslContextFactory.SslContextOptions options =
                SpiffeSslContextFactory.SslContextOptions
                        .builder()
                        .x509Source(x509Source)
                        .build();
        try {
            SpiffeSslContextFactory.getSslContext(options);
            fail();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            fail(e);
        } catch (IllegalArgumentException e) {
            assertEquals("SSL context should be configured either with a Supplier " +
                    "of accepted SPIFFE IDs or with acceptAnySpiffeId=true", e.getMessage());
        }
    }
}