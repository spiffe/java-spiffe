package spiffe;

import lombok.EqualsAndHashCode;

import java.util.Arrays;
import java.util.LinkedHashSet;

@EqualsAndHashCode
public class Algorithm {

    /**
     * ECDSA signature algorithm using SHA-256 hash algorithm.
     */
    public static final Algorithm ES256 = new Algorithm("ES256");

    /**
     * ECDSA signature algorithm using SHA-384 hash algorithm.
     */
    public static final Algorithm ES384 = new Algorithm("ES384");

    /**
     * ECDSA signature algorithm using SHA-512 hash algorithm.
     */
    public static final Algorithm ES512 = new Algorithm("ES512");

    /**
     * RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm.
     */
    public static final Algorithm RS256 = new Algorithm("RS256");

    /**
     * RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm.
     */
    public static final Algorithm RS384 = new Algorithm("RS384");

    /**
     * RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm.
     */
    public static final Algorithm RS512 = new Algorithm("RS512");

    /**
     * RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256.
     */
    public static final Algorithm PS256 = new Algorithm("PS256");

    /**
     * RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384.
     */
    public static final Algorithm PS384 = new Algorithm("PS384");

    /**
     * RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512.
     */
    public static final Algorithm PS512 = new Algorithm("PS512");

    private final String name;

    public Algorithm(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static final class Family extends LinkedHashSet<Algorithm> {

        public static final Family RSA = new Family("RSA", RS256, RS384, RS512, PS256, PS384, PS512);
        public static final Family EC = new Family("EC", ES256, ES384, ES512);

        private final String name;

        public Family(String name, final Algorithm... algorithms) {
            super(Arrays.asList(algorithms));
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public static Family parse(final String s) {
            if (s.equals(RSA.getName())) {
                return RSA;
            } else if (s.equals(EC.getName())) {
                return EC;
            } else {
                return new Family(s);
            }
        }
    }

    public static Algorithm parse(final String s) {
        if (s.equals(RS256.getName())) {
            return RS256;
        } else if (s.equals(RS384.getName())) {
            return RS384;
        } else if (s.equals(RS512.getName())) {
            return RS512;
        } else if (s.equals(ES256.getName())) {
            return ES256;
        } else if (s.equals(ES384.getName())) {
            return ES384;
        } else if (s.equals(ES512.getName())) {
            return ES512;
        } else if (s.equals(PS256.getName())) {
            return PS256;
        } else if (s.equals(PS384.getName())) {
            return PS384;
        } else if (s.equals(PS512.getName())) {
            return PS512;
        } else {
            return new Algorithm(s);
        }
    }
}
