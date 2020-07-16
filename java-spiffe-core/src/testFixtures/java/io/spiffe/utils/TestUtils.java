package io.spiffe.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Util methods for generating KeyPairs, tokens, and other functionality used only to be used in testing.
 */
public class TestUtils {

    private TestUtils() {
    }

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

    public static String generateToken(Map<String, Object> claims, KeyPair keyPair, String keyId) {
        JWTClaimsSet jwtClaimsSet = buildJWTClaimSetFromClaimsMap(claims);
        return generateToken(jwtClaimsSet, keyPair, keyId);
    }

    public static String generateToken(JWTClaimsSet claims, KeyPair keyPair, String keyId) {
        try {
            JWSAlgorithm algorithm;
            JWSSigner signer;
            if ("EC".equals(keyPair.getPublic().getAlgorithm())) {
                algorithm = JWSAlgorithm.ES512;
                signer = new ECDSASigner(keyPair.getPrivate(), Curve.P_521);
            } else if ("RSA".equals(keyPair.getPublic().getAlgorithm())) {
                algorithm = JWSAlgorithm.RS512;
                signer = new RSASSASigner(keyPair.getPrivate());
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

    public static JWTClaimsSet buildJWTClaimSet(Set<String> audience, String spiffeId, Date expiration) {
        return new JWTClaimsSet.Builder()
                .subject(spiffeId)
                .expirationTime(expiration)
                .audience(new ArrayList<>(audience))
                .build();
    }

    public static JWTClaimsSet buildJWTClaimSetFromClaimsMap(Map<String, Object> claims) {
        return new JWTClaimsSet.Builder()
                .subject((String) claims.get("sub"))
                .expirationTime((Date) claims.get("exp"))
                .audience((List<String>) claims.get("aud"))
                .build();
    }

    public static void setEnvironmentVariable(String variableName, String value) throws Exception {
        Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");

        Field unmodifiableMapField = getField(processEnvironment, "theUnmodifiableEnvironment");
        Object unmodifiableMap = unmodifiableMapField.get(null);
        injectIntoUnmodifiableMap(variableName, value, unmodifiableMap);

        Field mapField = getField(processEnvironment, "theEnvironment");
        Map<String, String> map = (Map<String, String>) mapField.get(null);
        map.put(variableName, value);
    }

    public static Object invokeMethod(Class<?> clazz, String methodName, Object... args) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method method = clazz.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return method.invoke(args);
    }

    public static Field getField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field;
    }

    public static URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }

    private static void injectIntoUnmodifiableMap(String key, String value, Object map) throws ReflectiveOperationException {
        Class unmodifiableMap = Class.forName("java.util.Collections$UnmodifiableMap");
        Field field = getField(unmodifiableMap, "m");
        Object obj = field.get(map);
        ((Map<String, String>) obj).put(key, value);
    }
}
