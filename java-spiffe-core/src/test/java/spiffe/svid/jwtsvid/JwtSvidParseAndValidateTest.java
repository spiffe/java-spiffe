package spiffe.svid.jwtsvid;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import spiffe.bundle.jwtbundle.JwtBundle;
import spiffe.exception.AuthorityNotFoundException;
import spiffe.exception.BundleNotFoundException;
import spiffe.exception.JwtSvidException;
import spiffe.spiffeid.SpiffeId;
import spiffe.spiffeid.TrustDomain;

import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtSvidParseAndValidateTest {

    private static final String HS256TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG" +
            "4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

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
        KeyPair key1 = Keys.keyPairFor(SignatureAlgorithm.ES384);
        KeyPair key2 = Keys.keyPairFor(SignatureAlgorithm.ES384);
        KeyPair key3 = Keys.keyPairFor(SignatureAlgorithm.RS256);

        TrustDomain trustDomain = TrustDomain.of("test.domain");
        JwtBundle jwtBundle = new JwtBundle(trustDomain);
        jwtBundle.addJWTAuthority("authority1", key1.getPublic());
        jwtBundle.addJWTAuthority("authority2", key2.getPublic());

        SpiffeId spiffeId = trustDomain.newSpiffeId("host");
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        List<String> audience = Collections.singletonList("audience");

        Claims claims = buildClaims(audience, spiffeId.toString(), expiration);

        return Stream.of(
                Arguments.of(TestCase.builder()
                        .name("success")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key1, "authority1"))
                        .expectedException(null)
                        .expectedJwtSvid(new JwtSvid(
                                trustDomain.newSpiffeId("host"),
                                audience,
                                expiration,
                                claims, null))
                        .build()),
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
                        .expectedAudience(audience)
                        .generateToken(() -> HS256TOKEN)
                        .expectedException(new JwtSvidException("Unsupported token signature algorithm HS256"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing subject")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(buildClaims(audience, "", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing subject claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing expiration")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(buildClaims(audience, spiffeId.toString(), null), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token missing expiration claim"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("token has expired")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(buildClaims(audience, spiffeId.toString(), new Date()), key1, "authority1"))
                        .expectedException(new JwtSvidException("Token has expired"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("unexpected audience")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(Collections.singletonList("another"))
                        .generateToken(() -> generateToken(claims, key1, "authority1"))
                        .expectedException(new JwtSvidException("expected audience in [another] (audience=[audience])"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("invalid subject claim")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(buildClaims(audience, "non-spiffe-subject", expiration), key1, "authority1"))
                        .expectedException(new JwtSvidException("Subject non-spiffe-subject cannot be parsed as a SPIFFE ID"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("missing key id")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key1, ""))
                        .expectedException(new JwtSvidException("Token header missing key id"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("no bundle for trust domain")
                        .jwtBundle(new JwtBundle(TrustDomain.of("other.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key1, "authority1"))
                        .expectedException(new BundleNotFoundException("No JWT bundle found for trust domain test.domain"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("no authority found for key id")
                        .jwtBundle(new JwtBundle(TrustDomain.of("test.domain")))
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key1, "authority1"))
                        .expectedException(new AuthorityNotFoundException("No authority found for the trust domain test.domain and key id authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("signature cannot be verified with authority")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key2, "authority1"))
                        .expectedException(new JwtSvidException("Signature invalid: cannot be verified with the authority with keyId=authority1"))
                        .build()),
                Arguments.of(TestCase.builder()
                        .name("authority algorithm mismatch")
                        .jwtBundle(jwtBundle)
                        .expectedAudience(audience)
                        .generateToken(() -> generateToken(claims, key3, "authority1"))
                        .expectedException(new JwtSvidException("Authority mismatch: signature cannot be verified with the authority with keyId=authority1"))
                        .build())
        );
    }

    private static String generateToken(Map<String, Object> claims, KeyPair key, String keyId) {
        return Jwts.builder()
                .setClaims(claims)
                .signWith(key.getPrivate())
                .setHeaderParam("kid", keyId)
                .compact();
    }

    private static Claims buildClaims(List<String> audience, String spiffeId, Date expiration) {
        Claims claims = new DefaultClaims();
        claims.put("aud", audience);
        claims.setSubject(spiffeId);
        claims.setExpiration(expiration);
        return claims;
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