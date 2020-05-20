package spiffe.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

/**
 * Util methods for generating KeyPairs, tokens, and other functionality used only to be used in testing.
 */
public class TestUtils {

    public static KeyPair generateECKeyPair(Curve curve) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(curve.getStdName()), new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair generateRSAKeyPair(int keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair generateDSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String generateToken(JWTClaimsSet claims, KeyPair key, String keyId) {
        try {
            JWSAlgorithm algorithm;
            JWSSigner signer;
            if ("EC".equals(key.getPublic().getAlgorithm())) {
                algorithm = JWSAlgorithm.ES512;
                signer = new ECDSASigner(key.getPrivate(), Curve.P_521);
            } else if ("RSA".equals(key.getPublic().getAlgorithm())) {
                algorithm = JWSAlgorithm.RS512;
                signer = new RSASSASigner(key.getPrivate());
            } else {
                throw new IllegalArgumentException("Algorithm not supported");
            }

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(keyId).build(), claims);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Could not generate token", e);
        }
    }

    public static JWTClaimsSet buildJWTClaimSet(List<String> audience, String spiffeId, Date expiration) {
        return new JWTClaimsSet.Builder()
                .subject(spiffeId)
                .expirationTime(expiration)
                .audience(audience)
                .build();
    }
}
