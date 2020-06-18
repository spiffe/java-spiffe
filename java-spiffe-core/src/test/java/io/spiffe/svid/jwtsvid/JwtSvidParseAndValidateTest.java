package io.spiffe.svid.jwtsvid;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSvidException;
import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.TestUtils;

import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtSvidParseAndValidateTest {

    private static final String HS256TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGhvcml0eTEifQ.eyJzdWIiOiJ" +
            "zcGlmZmU6Ly90ZXN0LmRvbWFpbi9ob3N0IiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxMjM0MzQzNTM0NTUsImlhdCI6MTUxNjIzOTAyMn0." +
            "TWSPgMbs227cbZxSLg247Uuag0Kz72cuSpJuozcMddA";

    @ParameterizedTest
    @MethodSource("provideJwtScenarios")
    void parseAndValidateJwt(TestCase testCase) {

        try {
            String token = testCase.generateToken.get();
            JwtSvid jwtSvid = JwtSvid.parseAndValidate(token, testCase.jwtBundle, testCase.audience);

            assertEquals(testCase.expectedJwtSvid.getSpiffeId(), jwtSvid.getSpiffeId());
            assertEquals(testCase.expectedJwtSvid.getAudience(), jwtSvid.getAudience());
            assertEquals(testCase.expectedJwtSvid.getExpiry().toInstant().getEpochSecond(), jwtSvid.getExpiry().toInstant().getEpochSecond());
            assertEquals(token, jwtSvid.getToken());
            assertEquals(token, jwtSvid.marshall());
        } catch (Exception e) {
            assertEquals(testCase.expectedException.getClass(), e.getClass());
            assertEquals(testCase.expectedException.getMessage(), e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullToken_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.of("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        List<String> audience = Collections.singletonList("audience");

        try {
            JwtSvid.parseAndValidate(null, jwtBundle, audience);
        } catch (NullPointerException e) {
            assertEquals("token is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_emptyToken_throwsIllegalArgumentException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.of("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        List<String> audience = Collections.singletonList("audience");

        try {
            JwtSvid.parseAndValidate("", jwtBundle, audience);
        } catch (IllegalArgumentException e) {
            assertEquals("Token cannot be blank", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullBundle_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        List<String> audience = Collections.singletonList("audience");
        try {
            JwtSvid.parseAndValidate("token", null, audience);
        } catch (NullPointerException e) {
            assertEquals("jwtBundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullAudience_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.of("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        List<String> audience = Collections.singletonList("audience");

        try {
            JwtSvid.parseAndValidate("token", jwtBundle, null);
        } catch (NullPointerException e) {
            assertEquals("audience is marked non-null but is null", e.getMessage());
        }
    }

    static Stream<Arguments> provideJwtScenarios() {
        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key3 = TestUtils.generateRSAKeyPair(2048);

        TrustDomain trustDomain = TrustDomain.of("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.putJwtAuthority("authority1", key1.getPublic());
        jwtBundle.putJwtAuthority("authority2", key2.getPublic());
        jwtBundle.putJwtAuthority("authority3", key3.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("host");
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        List<String> audience = Collections.singletonList("audience");

        JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("1. success using EC signature")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(null)
                        .expectedJwtSvid(new JwtSvid(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                expiration,
                                claims.getClaims(), null))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("2. success using RSA signature")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key3, "authority3"))
                        .expectedException(null)
                        .expectedJwtSvid(new JwtSvid(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                expiration,
                                claims.getClaims(), null))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("3. malformed")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> "invalid token")
                        .expectedException(new IllegalArgumentException("Unable to parse JWT token"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("4. unsupported algorithm")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> HS256TOKEN)
                        .expectedException(new JwtSvidException("Unsupported token signature algorithm HS256"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("5. missing subject")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing subject claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("6. missing expiration")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), null), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing expiration claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("7. token has expired")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), new Date()), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token has expired"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("8. unexpected audience")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(Collections.singletonList("another"))
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new JwtSvidException("expected audience in [another] (audience=[audience])"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("9. invalid subject claim")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "non-spiffe-subject", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Subject non-spiffe-subject cannot be parsed as a SPIFFE ID"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("10. missing key id")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, ""))
                        .expectedException(new JwtSvidException("Token header missing key id"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("11. no bundle for trust domain")
                        .jwtBundle(new JwtBundle(TrustDomain.of("other.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new BundleNotFoundException("No JWT bundle found for trust domain test.domain"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("12. no authority found for key id")
                        .jwtBundle(new JwtBundle(TrustDomain.of("test.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new AuthorityNotFoundException("No authority found for the trust domain test.domain and key id authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("13. signature cannot be verified with authority")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key2, "authority1"))
                        .expectedException(new JwtSvidException("Signature invalid: cannot be verified with the authority with keyId=authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("14. authority algorithm mismatch")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key3, "authority1"))
                        .expectedException(new JwtSvidException("Error verifying signature with the authority with keyId=authority1"))
                        .build())
        );
    }

    @Value
    static class TestCase {
        String name;
        JwtBundle jwtBundle;
        List<String> audience;
        Supplier<String> generateToken;
        Exception expectedException;
        JwtSvid expectedJwtSvid;

        @Builder
        public TestCase(String name, JwtBundle jwtBundle, List<String> expectedAudience, Supplier<String> generateToken,
                        Exception expectedException, JwtSvid expectedJwtSvid) {
            this.name = name;
            this.jwtBundle = jwtBundle;
            this.audience = expectedAudience;
            this.generateToken = generateToken;
            this.expectedException = expectedException;
            this.expectedJwtSvid = expectedJwtSvid;
        }
    }
}