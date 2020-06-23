package io.spiffe.internal;

public enum PrivateKeyAlgorithm {
    RSA,
    EC;

    public static PrivateKeyAlgorithm parse(String a) {
        if ("RSA".equalsIgnoreCase(a)) {
            return RSA;
        } else if ("EC".equalsIgnoreCase(a)) {
            return EC;
        } else {
            throw new IllegalArgumentException(String.format("Algorithm not recognized: %s", a));
        }
    }
}
