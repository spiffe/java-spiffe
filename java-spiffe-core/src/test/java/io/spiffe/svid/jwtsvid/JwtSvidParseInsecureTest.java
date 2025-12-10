package io.spiffe.svid.jwtsvid;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import io.spiffe.bundle.jwtbundle.JwtBundle;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class JwtSvidParseInsecureTest {

    @ParameterizedTest
    @MethodSource("provideSuccessScenarios")
    void parseValidJwt(TestCase testCase) {
        try {
            String token = testCase.generateToken.get();
            JwtSvid jwtSvid = JwtSvid.parseInsecure(token, testCase.expectedAudience, testCase.hint);

            assertEquals(testCase.expectedJwtSvid.getSpiffeId(), jwtSvid.getSpiffeId());
            assertEquals(testCase.expectedJwtSvid.getAudience(), jwtSvid.getAudience());
            assertEquals(testCase.expectedJwtSvid.getHint(), jwtSvid.getHint());
            assertEquals(testCase.expectedJwtSvid.getExpiry().toInstant().getEpochSecond(), jwtSvid.getExpiry().toInstant().getEpochSecond());
            assertEquals(token, jwtSvid.getToken());
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest
    @MethodSource("provideFailureScenarios")
    void parseInvalidJwt(TestCase testCase) {
        try {
            String token = testCase.generateToken.get();
            JwtSvid.parseInsecure(token, testCase.expectedAudience);
            fail("expected error: " + testCase.expectedException.getMessage());
        } catch (Exception e) {
            assertEquals(testCase.expectedException.getClass(), e.getClass());
            assertEquals(testCase.expectedException.getMessage(), e.getMessage());
        }

    }

    @Test
    void testParseInsecure_nullToken_throwsNullPointerException() throws JwtSvidException {
        Set<String> audience = Collections.singleton("audience");

        try {
            JwtSvid.parseInsecure(null, audience);
        } catch (NullPointerException e) {
            assertEquals("token must not be null", e.getMessage());
        }
    }

    @Test
    void testParseAndValidate_emptyToken_throwsIllegalArgumentException() throws JwtSvidException {
        Set<String> audience = Collections.singleton("audience");
        try {
            JwtSvid.parseInsecure("", audience);
        } catch (IllegalArgumentException e) {
            assertEquals("token cannot be blank", e.getMessage());
        }
    }

    @Test
    void testParseInsecure_nullAudience_throwsNullPointerException() throws JwtSvidException {
        try {
            KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
            TrustDomain trustDomain = TrustDomain.parse("test.domain");
            SpiffeId spiffeId = trustDomain.newSpiffeId("/host");
            Set<String> audience = Collections.singleton("audience");
            Date expiration = new Date(System.currentTimeMillis() + 3600000);
            JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

            JwtSvid.parseInsecure(TestUtils.generateToken(claims, key1, "authority1"), null);

        } catch (NullPointerException e) {
            assertEquals("audience must not be null", e.getMessage());
        }
    }

    static Stream<Arguments> provideSuccessScenarios() {
        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateECKeyPair(Curve.P_521);

        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.putJwtAuthority("authority1", key1.getPublic());
        jwtBundle.putJwtAuthority("authority2", key2.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("host");
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        Date issuedAt = new Date();
        Set<String> audience = Collections.singleton("audience");

        JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("using typ as JWT")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JWT))
                        .expectedException(null)
                        .hint("internal")
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                issuedAt,
                                expiration,
                                claims.getClaims(),
                                TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JWT),
                                "internal"
                        ))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("using typ as JOSE")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JOSE))
                        .expectedException(null)
                        .hint("external")
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                issuedAt,
                                expiration,
                                claims.getClaims(),
                                TestUtils.generateToken(claims, key1, "authority1", JwtSvid.HEADER_TYP_JWT),
                                "external"
                        ))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("using empty typ")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", ""))
                        .expectedException(null)
                        .hint("")
                        .expectedJwtSvid(newJwtSvidInstance(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                issuedAt,
                                expiration,
                                claims.getClaims(),
                                TestUtils.generateToken(claims, key1, "authority1", ""),
                                ""
                        ))
                        .build()));
    }

    static Stream<Arguments> provideFailureScenarios() {
        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateECKeyPair(Curve.P_521);

        TrustDomain trustDomain = TrustDomain.parse("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.putJwtAuthority("authority1", key1.getPublic());
        jwtBundle.putJwtAuthority("authority2", key2.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("host");
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        Set<String> audience = Collections.singleton("audience");

        JWTClaimsSet claims = TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("malformed")
                        .expectedAudience(audience)
                        .generateToken(() -> "invalid token")
                        .expectedException(new IllegalArgumentException("Unable to parse JWT token"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing subject")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing subject claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing expiration")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), null), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing expiration claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("token has expired")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, spiffeId.toString(), new Date()), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token has expired"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("unexpected audience")
                        .expectedAudience(Collections.singleton("another"))
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1"))
                        .expectedException(new JwtSvidException("expected audience in [another] (audience=[audience])"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("invalid subject claim")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(TestUtils.buildJWTClaimSet(audience, "non-spiffe-subject", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Subject non-spiffe-subject cannot be parsed as a SPIFFE ID"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("not valid header 'typ'")
                        .expectedAudience(audience)
                        .generateToken(() -> TestUtils.generateToken(claims, key1, "authority1", "OTHER"))
                        .expectedException(new JwtSvidException("If JWT header 'typ' is present, it must be either 'JWT' or 'JOSE'. Got: 'OTHER'."))
                        .build())
        );
    }

    static class TestCase {
        String name;
        Set<String> expectedAudience;
        String hint;
        Supplier<String> generateToken;
        Exception expectedException;
        JwtSvid expectedJwtSvid;

        public TestCase(String name,
                        Set<String> expectedAudience,
                        Supplier<String> generateToken,
                        Exception expectedException,
                        JwtSvid expectedJwtSvid,
                        String hint) {

            this.name = name;
            this.expectedAudience = expectedAudience;
            this.generateToken = generateToken;
            this.expectedException = expectedException;
            this.expectedJwtSvid = expectedJwtSvid;
            this.hint = hint;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String name;
            private Set<String> expectedAudience;
            private Supplier<String> generateToken;
            private Exception expectedException;
            private JwtSvid expectedJwtSvid;
            private String hint;

            public Builder name(String name) {
                this.name = name;
                return this;
            }

            public Builder expectedAudience(Set<String> audience) {
                this.expectedAudience = audience;
                return this;
            }

            public Builder generateToken(Supplier<String> generateToken) {
                this.generateToken = generateToken;
                return this;
            }

            public Builder expectedException(Exception expectedException) {
                this.expectedException = expectedException;
                return this;
            }

            public Builder expectedJwtSvid(JwtSvid expectedJwtSvid) {
                this.expectedJwtSvid = expectedJwtSvid;
                return this;
            }

            public Builder hint(String hint) {
                this.hint = hint;
                return this;
            }

            public TestCase build() {
                return new TestCase(
                        name,
                        expectedAudience,
                        generateToken,
                        expectedException,
                        expectedJwtSvid,
                        hint
                );
            }
        }
    }

    static JwtSvid newJwtSvidInstance(final SpiffeId spiffeId,
                                      final Set<String> audience,
                                      final Date issuedAt,
                                      final Date expiry,
                                      final Map<String, Object> claims,
                                      final String token,
                                      final String hint
    ) {
        final Constructor<?> constructor = JwtSvid.class.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        try {
            return (JwtSvid) constructor.newInstance(spiffeId, audience, issuedAt, expiry, claims, token, hint);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

}