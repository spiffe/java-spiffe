package io.spiffe.provider;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.Certificate;
import java.util.Enumeration;

import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpiffeKeyStoreTest {

    private static SpiffeKeyStore spiffeKeyStore;

    @BeforeAll
    static void setup() {
        spiffeKeyStore = new SpiffeKeyStore();
    }
    @Test
    void engineGetKey() {
        assertNull(spiffeKeyStore.engineGetKey("alias", "pass".toCharArray()));
    }

    @Test
    void engineGetCertificateChain() {
        Certificate[] chain = spiffeKeyStore.engineGetCertificateChain("alias");
        assertEquals(0, chain.length);
    }

    @Test
    void engineGetCertificate() {
        assertNull(spiffeKeyStore.engineGetCertificate("alias"));
    }

    @Test
    void engineGetCreationDate() {
        assertNotNull(spiffeKeyStore.engineGetCreationDate("alias"));
    }

    @Test
    void engineSetKeyEntry() {
        spiffeKeyStore.engineSetKeyEntry("alias", null, null);
        spiffeKeyStore.engineSetKeyEntry("alias", null, null, null);
    }

    @Test
    void testEngineSetKeyEntry() {
        spiffeKeyStore.engineSetKeyEntry("alias", null, null);
        spiffeKeyStore.engineSetKeyEntry("alias", null, null, null);
    }

    @Test
    void engineSetCertificateEntry() {
        spiffeKeyStore.engineSetCertificateEntry("alias", null);
    }

    @Test
    void engineDeleteEntry() {
        spiffeKeyStore.engineDeleteEntry("alias");
    }

    @Test
    void engineAliases() {
        Enumeration<String> enumeration = spiffeKeyStore.engineAliases();
        assertEquals(DEFAULT_ALIAS, enumeration.nextElement());
    }

    @Test
    void engineContainsAlias() {
        assertTrue(spiffeKeyStore.engineContainsAlias(DEFAULT_ALIAS));
    }

    @Test
    void engineSize() {
        assertEquals(1, spiffeKeyStore.engineSize());
    }

    @Test
    void engineIsKeyEntry() {
        assertTrue(spiffeKeyStore.engineIsKeyEntry(DEFAULT_ALIAS));
        assertFalse(spiffeKeyStore.engineIsKeyEntry("alias"));
    }

    @Test
    void engineIsCertificateEntry() {
        assertTrue(spiffeKeyStore.engineIsCertificateEntry(DEFAULT_ALIAS));
        assertFalse(spiffeKeyStore.engineIsCertificateEntry("alias"));
    }

    @Test
    void engineGetCertificateAlias() {
        assertEquals(DEFAULT_ALIAS, spiffeKeyStore.engineGetCertificateAlias(null));
    }

    @Test
    void engineStore() {
        spiffeKeyStore.engineStore(null, null);
    }

    @Test
    void engineLoad() {
        spiffeKeyStore.engineLoad(null, null);
    }
}