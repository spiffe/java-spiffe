package io.spiffe.provider;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Objects;

import static java.util.Collections.enumeration;
import static io.spiffe.provider.SpiffeProviderConstants.DEFAULT_ALIAS;

/**
 * This class is required by the Java Provider Architecture, but since this Provider
 * doesn't use certificates stored in a KeyStore, the only purpose of this class is
 * to return the ALIAS that is handled by this SPIFFE Provider implementation.
 */
public final class SpiffeKeyStore extends KeyStoreSpi {

    private static final int NUMBER_OF_ENTRIES = 1;

    @Override
    public Key engineGetKey(final String alias, final char[] password) {
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
        return new Certificate[0];
    }

    @Override
    public Certificate engineGetCertificate(final String alias) {
        return null;
    }

    @Override
    public Date engineGetCreationDate(final String alias) {
        return Date.from(Instant.now());
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) {
        //no implementation needed
    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) {
        //no implementation needed
    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) {
        //no implementation needed
    }

    @Override
    public void engineDeleteEntry(final String alias) {
        //no implementation needed
    }

    @Override
    public Enumeration<String> engineAliases() {
        return enumeration(Collections.singletonList(DEFAULT_ALIAS));
    }

    @Override
    public boolean engineContainsAlias(final String alias) {
        return Objects.equals(alias, DEFAULT_ALIAS);
    }

    @Override
    public int engineSize() {
        return NUMBER_OF_ENTRIES;
    }

    @Override
    public boolean engineIsKeyEntry(final String alias) {
        return Objects.equals(alias, DEFAULT_ALIAS);
    }

    @Override
    public boolean engineIsCertificateEntry(final String alias) {
        return Objects.equals(alias, DEFAULT_ALIAS);
    }

    @Override
    public String engineGetCertificateAlias(final Certificate cert) {
        return DEFAULT_ALIAS;
    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password) {
        //no implementation needed
    }

    @Override
    public void engineLoad(final InputStream stream, final char[] password) {
        //no implementation needed
    }
}
