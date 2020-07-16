package io.spiffe.internal;

public enum AsymmetricKeyAlgorithm {

    RSA("RSA"),
    EC("EC");

    private final String value;

    AsymmetricKeyAlgorithm(final String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static AsymmetricKeyAlgorithm parse(String a) {
        if ("RSA".equalsIgnoreCase(a)) {
            return RSA;
        } else if ("EC".equalsIgnoreCase(a)) {
            return EC;
        } else {
            throw new IllegalArgumentException(String.format("Algorithm not supported: %s", a));
        }
    }
}
