package spiffe.provider;

import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Date;
import java.util.Enumeration;
import java.util.Objects;

import static java.util.Collections.enumeration;
import static spiffe.provider.SpiffeProviderConstants.ALIAS;

/**
 * This class is required for the Java Provider Architecture,  but since this Provider doesn't use certificates
 * stored in a KeyStore, this class doesn't handle the Certificates, but only returns the ALIAS that is handled
 * by the Provider
 *
 */
public class SpiffeKeyStore extends KeyStoreSpi {

    private static final int NUMBER_OF_ENTRIES = 1;

    @Override
    public Key engineGetKey(String alias, char[] password) {
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return Date.from(Instant.now());
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {

    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {

    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {

    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {

    }

    @Override
    public Enumeration<String> engineAliases() {
        return enumeration(ImmutableList.of(ALIAS));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return Objects.equals(alias, ALIAS);
    }

    @Override
    public int engineSize() {
        return NUMBER_OF_ENTRIES;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return Objects.equals(alias, ALIAS);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return Objects.equals(alias, ALIAS);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return ALIAS;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {

    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {

    }
}
