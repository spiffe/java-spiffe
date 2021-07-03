package io.spiffe.svid.jwtsvid;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.TestUtils;
import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static io.spiffe.svid.jwtsvid.JwtSvidParseInsecureTest.newJwtSvidInstance;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class JwtSvidParseAndValidateTest {

    private static final String HS256TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGhvcml0eTEifQ." +
            "eyJzdWIiOiJzcGlmZmU6Ly90ZXN0LmRvbWFpbi9ob3N0IiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxMjM0MzQzNTM0NTUsImlh" +
            "dCI6MTUxNjIzOTAyMiwiYXVkIjoiYXVkaWVuY2UifQ.wNm5pQGSLCw5N9ddgSF2hkgmQpGnG9le_gpiFmyBhao";

    @ParameterizedTest
    @MethodSource("provideSuccessScenarios")
    void parseAndValidateValidJwt(TestCase testCase) {
        try {
            String token = testCase.generateToken.get();
            JwtSvid jwtSvid = JwtSvid.parseAndValidate(token, testCase.jwtBundle, testCase.audience);

            assertEquals(testCase.expectedJwtSvid.getSpiffeId(), jwtSvid.getSpiffeId());
            assertEquals(testCase.expectedJwtSvid.getAudience(), jwtSvid.getAudience());
            assertEquals(testCase.expectedJwtSvid.getExpiry().toInstant().getEpochSecond(), jwtSvid.getExpiry().toInstant().getEpochSecond());
            assertEquals(token, jwtSvid.getToken());
            assertEquals(token, jwtSvid.marshal());
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest
    @MethodSource("provideFailureScenarios")
    void parseAndValidateInvalidJwt(TestCase testCase) {
        try {
            String token = testCase.generateToken.get();
            JwtSvid.parseAndValidate(token, testCase.jwtBundle, testCase.audience);
            fail("expected error: " + testCase.expectedException.getMessage());
        } catch (Exception e) {
            assertEquals(testCase.expectedException.getClass(), e.getClass());
            assertEquals(testCase.expectedException.getMessage(), e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullToken_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        Set<String> audience = Collections.singleton("audience");

        try {
            JwtSvid.parseAndValidate(null, jwtBundle, audience);
        } catch (NullPointerException e) {
            assertEquals("token is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_emptyToken_throwsIllegalArgumentException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        Set<String> audience = Collections.singleton("audience");

        try {
            JwtSvid.parseAndValidate("", jwtBundle, audience);
        } catch (IllegalArgumentException e) {
            assertEquals("Token cannot be blank", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullBundle_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        Set<String> audience = Collections.singleton("audience");
        try {
            JwtSvid.parseAndValidate("token", null, audience);
        } catch (NullPointerException e) {
            assertEquals("jwtBundleSource is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_nullAudience_throwsNullPointerException() throws JwtSvidException, AuthorityNotFoundException, BundleNotFoundException {
        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);

        try {
            JwtSvid.parseAndValidate("token", jwtBundle, null);
        } catch (NullPointerException e) {
            assertEquals("audience is marked non-null but is null", e.getMessage());
        }
    }

    static Stream<Arguments> provideSuccessScenarios() {
        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key3 = TestUtils.generateRSAKeyPair(2048);

        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.putJwtAuthority("authority1", key1.getPublic());
        jwtBundle.putJwtAuthority("authority2", key2.getPublic());
        jwtBundle.putJwtAuthority("authority3", key3.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("/host");
        Date expiration = new Date(System.currentTimeMillis() +  (60 * 60 * 1000));
        Set<String> audience = new HashSet<String>() {{add("audience1"); add("audience2");}};

        JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("using EC signature")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(Collections.singleton("audience1"))
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JOSE))
                        .expectedException(null)
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("/host"),
                                audience,
                                expiration,
                                claims.getClaims(), TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JOSE) ))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("using RSA signature")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key3, "authority3", JwtSvid.HEADER_TYP_JWT))
                        .expectedException(null)
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("/host"),
                                audience,
                                expiration,
                                claims.getClaims(), TestUtils.generateToken(claims, key3, "authority3", JwtSvid.HEADER_TYP_JWT)))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("using empty typ")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key3, "authority3", ""))
                        .expectedException(null)
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("/host"),
                                audience,
                                expiration,
                                claims.getClaims(), TestUtils.generateToken(claims, key3, "authority3")))
                        .build())
        );
    }

    static Stream<Arguments> provideFailureScenarios() {
        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key3 = TestUtils.generateRSAKeyPair(2048);

        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.putJwtAuthority("authority1", key1.getPublic());
        jwtBundle.putJwtAuthority("authority2", key2.getPublic());
        jwtBundle.putJwtAuthority("authority3", key3.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("/host");
        Date expiration = new Date(System.currentTimeMillis() +  (60 * 60 * 1000));
        Set<String> audience = new HashSet<String>() {{add("audience1"); add("audience2");}};

        JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("malformed")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> "invalid token")
                        .expectedException(new IllegalArgumentException("Unable to parse JWT token"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("unsupported algorithm")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(Collections.singleton("audience"))
                        .generateToken(() -> HS256TOKEN)
                        .expectedException(new JwtSvidException("Unsupported JWT algorithm: HS256"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing subject")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing subject claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing expiration")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), null), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing expiration claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("token has expired")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), new Date()), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token has expired"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("unexpected audience")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(Collections.singleton("another"))
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new JwtSvidException("expected audience in [another] (audience=[audience2, audience1])"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("invalid subject claim")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "non-spiffe-subject", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Subject non-spiffe-subject cannot be parsed as a SPIFFE ID"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing key id")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, null))
                        .expectedException(new JwtSvidException("Token header missing key id"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("key id contains an empty value")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "   "))
                        .expectedException(new JwtSvidException("Token header key id contains an empty value"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("no bundle for trust domain")
                        .jwtBundle(new JwtBundle(TrustDomain.parse("other.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new BundleNotFoundException("No JWT bundle found for trust domain test.domain"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("no authority found for key id")
                        .jwtBundle(new JwtBundle(TrustDomain.parse("test.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new AuthorityNotFoundException("No authority found for the trust domain test.domain and key id authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("signature cannot be verified with authority")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key2, "authority1"))
                        .expectedException(new JwtSvidException("Signature invalid: cannot be verified with the authority with keyId=authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("authority algorithm mismatch")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key3, "authority1"))
                        .expectedException(new JwtSvidException("Error verifying signature with the authority with keyId=authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("not valid header 'typ'")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", "OTHER"))
                        .expectedException(new JwtSvidException("If JWT header 'typ' is present, it must be either 'JWT' or 'JOSE'. Got: 'OTHER'."))
                        .build())
        );
    }

    @Value
    static class TestCase {
        String name;
        JwtBundle jwtBundle;
        Set<String> audience;
        Supplier<String> generateToken;
        Exception expectedException;
        JwtSvid expectedJwtSvid;

        @Builder
        public TestCase(String name, JwtBundle jwtBundle, Set<String> expectedAudience, Supplier<String> generateToken,
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