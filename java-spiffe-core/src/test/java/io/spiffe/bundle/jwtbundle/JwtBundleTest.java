package io.spiffe.bundle.jwtbundle;

import com.nimbusds.jose.jwk.Curve;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtBundleException;
import io.spiffe.internal.DummyPublicKey;
import io.spiffe.spiffeid.TrustDomain;
import io.spiffe.utils.TestUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JwtBundleTest {

    @Test
    void testNewJwtBundleWithTrustDomain_Success() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("example.org"), jwtBundle.getTrustDomain());
    }

    @Test
    void testNewJwtBundleWithTrustDomainAndAuthorities_Success() {
        HashMap<String, PublicKey> authorities = new HashMap<>();

        KeyPair key1 = TestUtils.generateECKeyPair(Curve.P_521);
        KeyPair key2 = TestUtils.generateRSAKeyPair(2048);

        authorities.put("authority1", key1.getPublic());
        authorities.put("authority2", key2.getPublic());

        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"), authorities);

        // change a key in the map, to test that the bundle has its own copy
        authorities.put("authority1", key2.getPublic());

        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("example.org"), jwtBundle.getTrustDomain());
        assertEquals(2, jwtBundle.getJwtAuthorities().size());
        assertEquals(key1.getPublic(), jwtBundle.getJwtAuthorities().get("authority1"));
        assertEquals(key2.getPublic(), jwtBundle.getJwtAuthorities().get("authority2"));
    }

    @Test
    void testNewJwtBundle_TrustDomainIsNull_ThrowsNullPointerException() {
        try {
            HashMap<String, PublicKey> authorities = new HashMap<>();
            new JwtBundle(null, authorities);
            fail("NullPointerException was expected");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testNewJwtBundleWithTrustDomain_AuthoritiesIsNull_ThrowsNullPointerException() {
        try {
            new JwtBundle(TrustDomain.parse("example.org"), null);
            fail("NullPointerException was expected");
        } catch (NullPointerException e) {
            assertEquals("jwtAuthorities is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testNewJwtBundleWithAuthorities_TrustDomainIsNull_ThrowsNullPointerException() {
        try {
            new JwtBundle(null);
            fail("NullPointerException was expected");
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testLoadFileWithEcKey_Success() throws URISyntaxException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_valid_EC_1.json"));
        TrustDomain trustDomain = TrustDomain.parse("example.org");

        JwtBundle jwtBundle = null;
        try {
            jwtBundle = JwtBundle.load(trustDomain, path);
        } catch (KeyException | JwtBundleException e) {
            fail();
        }

        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("example.org"), jwtBundle.getTrustDomain());
        assertEquals(1, jwtBundle.getJwtAuthorities().size());
        assertNotNull(jwtBundle.getJwtAuthorities().get("C6vs25welZOx6WksNYfbMfiw9l96pMnD"));
    }

    @Test
    void testLoadFileWithRsaKey_Success() throws URISyntaxException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_valid_RSA_1.json"));
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        JwtBundle jwtBundle = null;
        try {
            jwtBundle = JwtBundle.load(trustDomain, path);
        } catch (KeyException | JwtBundleException e) {
            fail(e);
        }

        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("domain.test"), jwtBundle.getTrustDomain());
        assertEquals(1, jwtBundle.getJwtAuthorities().size());
        assertNotNull(jwtBundle.getJwtAuthorities().get("14cc39cd-838d-426d-9bb1-77f3468fba96"));
    }

    @Test
    void testLoadFileWithRsaAndEc_Success() throws URISyntaxException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_valid_RSA_EC.json"));
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        JwtBundle jwtBundle = null;
        try {
            jwtBundle = JwtBundle.load(trustDomain, path);
        } catch (KeyException | JwtBundleException e) {
            fail(e);
        }

        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("domain.test"), jwtBundle.getTrustDomain());
        assertEquals(2, jwtBundle.getJwtAuthorities().size());
        assertNotNull(jwtBundle.getJwtAuthorities().get("14cc39cd-838d-426d-9bb1-77f3468fba96"));
        assertNotNull(jwtBundle.getJwtAuthorities().get("C6vs25welZOx6WksNYfbMfiw9l96pMnD"));
    }

    @Test
    void testLoadFile_MissingKid_ThrowsJwtBundleException() throws URISyntaxException, KeyException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_missing_kid.json"));
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        try {
            JwtBundle.load(trustDomain, path);
            fail("should have thrown exception");
        } catch (JwtBundleException e) {
            assertEquals("Error adding authority of JWKS: keyID cannot be empty", e.getMessage());
        }
    }

    @Test
    void testLoadFile_InvalidKeyType_ThrowsKeyException() throws URISyntaxException, KeyException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_invalid_keytype.json"));
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        try {
            JwtBundle.load(trustDomain, path);
            fail("should have thrown exception");
        } catch (JwtBundleException e) {
            assertEquals("Unsupported JWT family algorithm: OKP", e.getCause().getMessage());
        }
    }

    @Test
    void testLoadFile_NonExistentFile_ThrowsException() throws KeyException {
        Path path = Paths.get("testdata/jwtbundle/non-existen.json");
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        try {
            JwtBundle.load(trustDomain, path);
            fail("should have thrown exception");
        } catch (JwtBundleException e) {
            assertEquals("Could not load bundle from file: testdata/jwtbundle/non-existen.json", e.getMessage());
        }
    }

    @Test
    void testLoad_NullTrustDomain_ThrowsNullPointerException() throws KeyException, JwtBundleException {
        try {
            JwtBundle.load(null, Paths.get("path-to-file"));
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testLoad_NullBundlePath_ThrowsNullPointerException() throws KeyException, JwtBundleException {
        try {
            JwtBundle.load(TrustDomain.parse("example.org"), null);
        } catch (NullPointerException e) {
            assertEquals("bundlePath is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParseJsonWithRsaAndEcKeys_Success() throws URISyntaxException, IOException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_valid_RSA_EC.json"));
        byte[] bundleBytes = Files.readAllBytes(path);

        JwtBundle jwtBundle = null;
        try {
            jwtBundle = JwtBundle.parse(TrustDomain.parse("domain.test"), bundleBytes);
        } catch (JwtBundleException e) {
            fail(e);
        }

        assertNotNull(jwtBundle);
        assertEquals(TrustDomain.parse("domain.test"), jwtBundle.getTrustDomain());
        assertEquals(2, jwtBundle.getJwtAuthorities().size());
        assertNotNull(jwtBundle.getJwtAuthorities().get("14cc39cd-838d-426d-9bb1-77f3468fba96"));
        assertNotNull(jwtBundle.getJwtAuthorities().get("C6vs25welZOx6WksNYfbMfiw9l96pMnD"));
    }

    @Test
    void testParse_MissingKid_Fails() throws URISyntaxException, IOException {
        Path path = Paths.get(toUri("testdata/jwtbundle/jwks_missing_kid.json"));
        byte[] bundleBytes = Files.readAllBytes(path);
        TrustDomain trustDomain = TrustDomain.parse("domain.test");

        try {
            JwtBundle.parse(trustDomain, bundleBytes);
            fail("should have thrown exception");
        } catch (JwtBundleException e) {
            assertEquals("Error adding authority of JWKS: keyID cannot be empty", e.getMessage());
        }
    }

    @Test
    void testParseInvalidJson() throws KeyException {
        try {
            JwtBundle.parse(TrustDomain.parse("example.org"), "invalid json".getBytes());
            fail("exception is expected");
        } catch (JwtBundleException e) {
            assertEquals("Could not parse bundle from bytes", e.getMessage());
        }
    }

    @Test
    void testParse_NullTrustDomain_ThrowsNullPointerException() throws KeyException, JwtBundleException {
        try {
            JwtBundle.parse(null, "json".getBytes());
        } catch (NullPointerException e) {
            assertEquals("trustDomain is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testParse_NullBundleBytes_ThrowsNullPointerException() throws KeyException, JwtBundleException {
        try {
            JwtBundle.parse(TrustDomain.parse("example.org"), null);
        } catch (NullPointerException e) {
            assertEquals("bundleBytes is marked non-null but is null", e.getMessage());
        }
    }


    @Test
    void testgetBundleForTrustDomain_Success() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        try {
            JwtBundle bundle = jwtBundle.getBundleForTrustDomain(TrustDomain.parse("example.org"));
            assertEquals(jwtBundle, bundle);
        } catch (BundleNotFoundException e) {
           fail(e);
        }
    }

    @Test
    void testgetBundleForTrustDomain_doesNotExiste_ThrowsBundleNotFoundException() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        try {
            jwtBundle.getBundleForTrustDomain(TrustDomain.parse("other.org"));
            fail("exception expected");
        } catch (BundleNotFoundException e) {
            assertEquals("No JWT bundle found for trust domain other.org", e.getMessage());
        }
    }

    @Test
    void testJWTAuthoritiesCRUD() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));

        // Test addJWTAuthority
        DummyPublicKey jwtAuthority1 = new DummyPublicKey();
        DummyPublicKey jwtAuthority2 = new DummyPublicKey();
        jwtBundle.putJwtAuthority("key1", jwtAuthority1);
        jwtBundle.putJwtAuthority("key2", jwtAuthority2);

        assertEquals(2, jwtBundle.getJwtAuthorities().size());

        // Test findJwtAuthority
        PublicKey key1 = null;
        PublicKey key2 = null;
        try {
            key1 = jwtBundle.findJwtAuthority("key1");
            key2 = jwtBundle.findJwtAuthority("key2");
        } catch (AuthorityNotFoundException e) {
            fail(e);
        }
        assertEquals(key1, jwtAuthority1 );
        assertEquals(key2, jwtAuthority2 );

        // Test RemoveJwtAuthority
        jwtBundle.removeJwtAuthority("key1");
        assertFalse(jwtBundle.hasJwtAuthority("key1"));
        assertTrue(jwtBundle.hasJwtAuthority("key2"));

        // Test update
        jwtBundle.putJwtAuthority("key2", jwtAuthority1);
        assertEquals(jwtAuthority1, jwtBundle.getJwtAuthorities().get("key2"));
        assertEquals(1, jwtBundle.getJwtAuthorities().size());
    }

    @Test
    void testAddJwtAuthority_emtpyKeyId_throwsIllegalArgumentException() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        try {
            jwtBundle.putJwtAuthority("", new DummyPublicKey());
        } catch (IllegalArgumentException e) {
            assertEquals("KeyId cannot be empty", e.getMessage());
        }
    }

    @Test
    void testAddJwtAuthority_nullKeyId_throwsNullPointerException() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        try {
            jwtBundle.putJwtAuthority(null, new DummyPublicKey());
        } catch (NullPointerException e) {
            assertEquals("keyId is marked non-null but is null", e.getMessage());
        }
    }

    @Test
    void testAddJwtAuthority_nullJwtAuthority_throwsNullPointerException() {
        JwtBundle jwtBundle = new JwtBundle(TrustDomain.parse("example.org"));
        try {
            jwtBundle.putJwtAuthority("key1", null);
        } catch (NullPointerException e) {
            assertEquals("jwtAuthority is marked non-null but is null", e.getMessage());
        }
    }
}