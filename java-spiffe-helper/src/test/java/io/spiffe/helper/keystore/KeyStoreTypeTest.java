package io.spiffe.helper.keystore;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class KeyStoreTypeTest {

    @Test
    void value() {
        assertEquals("jks", KeyStoreType.JKS.value());
        assertEquals("pkcs12", KeyStoreType.PKCS12.value());
    }

    @Test
    void testGetDefaultType() {
        assertEquals(KeyStoreType.PKCS12, KeyStoreType.getDefaultType());
    }

    @Test
    void testParseJKS() {
        final KeyStoreType type = KeyStoreType.parse("jks");
        assertEquals(KeyStoreType.JKS, type);
    }

    @Test
    void testParsePKCS12() {
        final KeyStoreType type = KeyStoreType.parse("pkcs12");
        assertEquals(KeyStoreType.PKCS12, type);
    }

    @Test
    void testParseUnknownType() {
        try {
            KeyStoreType.parse("other_unknown");
            fail("expected error: KeyStore type not supported");
        } catch (IllegalArgumentException e) {
            assertEquals("KeyStore type not supported: other_unknown", e.getMessage());
        }
    }
}