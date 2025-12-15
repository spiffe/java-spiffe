package io.spiffe.internal;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Represents JWT Signature Supported Algorithms.
 */
public enum JwtSignatureAlgorithm {

    /**
     * ECDSA algorithm using SHA-256 hash algorithm.
     */
    ES256("ES256"),

    /**
     * ECDSA algorithm using SHA-384 hash algorithm.
     */
    ES384("ES384"),

    /**
     * ECDSA algorithm using SHA-512 hash algorithm.
     */
    ES512("ES512"),

    /**
     * RSASSA-PKCS1-v1_5 algorithm using SHA-256 hash algorithm.
     */
    RS256("RS256"),

    /**
     * RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm.
     */
    RS384("RS384"),

    /**
     * RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm.
     */
    RS512("RS512"),

    /**
     * RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256.
     */
    PS256("PS256"),

    /**
     * RSASSA-PSS using SHA-384 and MGF1 padding with SHA-384.
     */
    PS384("PS384"),

    /**
     * RSASSA-PSS using SHA-512 and MGF1 padding with SHA-512.
     */
    PS512("PS512");

    private final String name;

    JwtSignatureAlgorithm(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    /**
     * Represents families of algorithms.
     */
    public enum Family {
        RSA("RSA", RS256, RS384, RS512, PS256, PS384, PS512),
        EC("EC", ES256, ES384, ES512);

        private final String name;
        private final Set<JwtSignatureAlgorithm> algorithms;

        Family(final String name, final JwtSignatureAlgorithm... algs) {
            this.name = name;
            algorithms = new HashSet<>();
            Collections.addAll(algorithms, algs);
        }

        public String getName() {
            return name;
        }

        public boolean contains(final JwtSignatureAlgorithm a) {
            return algorithms.contains(a);
        }

        public static Family parse(final String s) {
            final Family family;
            if (s.equals(RSA.getName())) {
                family = RSA;
            } else if (s.equals(EC.getName())) {
                family = EC;
            } else {
                throw new IllegalArgumentException("Unsupported JWT family algorithm: " + s);
            }
            return family;
        }
    }

    public static JwtSignatureAlgorithm parse(String s) {
        final JwtSignatureAlgorithm algorithm;
        if (s.equals(RS256.getName())) {
            algorithm = RS256;
        } else if (s.equals(RS384.getName())) {
            algorithm = RS384;
        } else if (s.equals(RS512.getName())) {
            algorithm = RS512;
        } else if (s.equals(ES256.getName())) {
            algorithm = ES256;
        } else if (s.equals(ES384.getName())) {
            algorithm = ES384;
        } else if (s.equals(ES512.getName())) {
            algorithm = ES512;
        } else if (s.equals(PS256.getName())) {
            algorithm = PS256;
        } else if (s.equals(PS384.getName())) {
            algorithm = PS384;
        } else if (s.equals(PS512.getName())) {
            algorithm = PS512;
        } else {
            throw new IllegalArgumentException("Unsupported JWT algorithm: " + s);
        }
        return algorithm;
    }
}
