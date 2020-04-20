package spiffe.svid.x509svid;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import spiffe.bundle.x509bundle.X509Bundle;
import spiffe.bundle.x509bundle.X509BundleSource;
import spiffe.internal.CertificateUtils;
import spiffe.result.Result;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class X509SvidValidatorTest {

    @Mock
    X509BundleSource bundleSourceMock;

    @BeforeEach
    void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void verifyChain_certificateExpired_returnsError() throws IOException {
        val certBytes = Files.readAllBytes(Paths.get("../testdata/x509cert.pem"));
        val chain = CertificateUtils.generateCertificates(certBytes).getValue();
        val x509BundleResult =
                X509Bundle.load(
                        TrustDomain.of("example.org").getValue(),
                        Paths.get("../testdata/bundle.pem")
                );
        val x509Bundle = x509BundleResult.getValue();

        when(bundleSourceMock
                .getX509BundleForTrustDomain(
                        TrustDomain.of("example.org").getValue()))
                .thenReturn(Result.ok(x509Bundle));

        val result = X509SvidValidator.verifyChain(chain, bundleSourceMock);

        assertTrue(result.isError());
        assertTrue(result.getError().contains("CertificateExpiredException: NotAfter"));
    }
    
    @Test
    void checkSpiffeId_givenASpiffeIdInTheListOfAcceptedIds_returnsValid() {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/test").getValue();
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/test2").getValue();

        Result<List<SpiffeId>, String> spiffeIdList = Result.ok(Arrays.asList(spiffeId1, spiffeId2));

        val result = X509SvidValidator
                .verifySpiffeId(SpiffeId.parse("spiffe://example.org/test").getValue(), () -> spiffeIdList);

        assertTrue(result.isOk());
    }

    @Test
    void checkSpiffeId_givenASpiffeIdNotInTheListOfAcceptedIds_returnsValid() {
        val spiffeId1 = SpiffeId.parse("spiffe://example.org/other1").getValue();
        val spiffeId2 = SpiffeId.parse("spiffe://example.org/other2").getValue();
        Result<List<SpiffeId>, String> spiffeIdList = Result.ok(Arrays.asList(spiffeId1, spiffeId2));

        val result = X509SvidValidator.verifySpiffeId(SpiffeId.parse("spiffe://example.org/test").getValue(), () -> spiffeIdList);

        assertAll(
                () -> assertTrue(result.isError()),
                () -> assertEquals("SPIFFE ID 'spiffe://example.org/test' is not accepted.",result.getError())
        );
    }
}
