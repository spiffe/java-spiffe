package io.spiffe.internal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AsymmetricKeyAlgorithmTest {

    @Test
    void parseRSA() {
        AsymmetricKeyAlgorithm algorithm = AsymmetricKeyAlgorithm.parse("RSA");
        assertEquals(AsymmetricKeyAlgorithm.RSA, algorithm);
    }

    @Test
    void parseEC() {
        AsymmetricKeyAlgorithm algorithm = AsymmetricKeyAlgorithm.parse("EC");
        assertEquals(AsymmetricKeyAlgorithm.EC, algorithm);
    }

    @Test
    void parseUnknown() {
        try {
            AsymmetricKeyAlgorithm.parse("unknown");
        } catch (IllegalArgumentException e) {
            assertEquals("Algorithm not supported: unknown", e.getMessage());
        }
    }
}