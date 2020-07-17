package io.spiffe.provider;

import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EnvironmentUtilsTest {

    @Test
    void getPropertyFromSystem() {
        System.setProperty("testVariable", "example");
        String value = EnvironmentUtils.getProperty("testVariable");
        assertEquals("example", value);
    }

    @Test
    void getPropertyFromSecurity() {
        Security.setProperty("testVariable", "example");
        String value = EnvironmentUtils.getProperty("testVariable");
        assertEquals("example", value);
    }

    @Test
    void getSecurityPropertyWithDefaultValue() {
        Security.setProperty("testVariable", "example");
        String value = EnvironmentUtils.getProperty("otherVariable", "default");
        assertEquals("default", value);
    }

    @Test
    void getSystemPropertyWithDefaultValue() {
        System.setProperty("testVariable", "example");
        String value = EnvironmentUtils.getProperty("testVariable", "default");
        assertEquals("example", value);
    }

    @Test
    void getPropertyReturnBlankForNotFoundVariable() {
        String value = EnvironmentUtils.getProperty("unknown");
        assertEquals("", value);
    }
}