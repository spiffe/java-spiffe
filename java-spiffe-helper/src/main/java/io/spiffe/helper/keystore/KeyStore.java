package io.spiffe.helper.keystore;

import io.spiffe.exception.InvalidSpiffeIdException;
import io.spiffe.spiffeid.TrustDomain;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Represents a Java KeyStore, provides some functions
 * to store a private key, an X.509 certificate chain, and X.509 bundles.
 * Package private, to be used by the KeyStoreHelper.
 */
class KeyStore {

    private final Path keyStoreFilePath;
    private final KeyStoreType keyStoreType;
    private final String keyStorePassword;
    private java.security.KeyStore javaKeyStore;

    KeyStore(
            Path keyStoreFilePath,
            KeyStoreType keyStoreType,
            String keyStorePassword) throws KeyStoreException {

        this.keyStoreFilePath = Objects.requireNonNull(keyStoreFilePath, "keyStoreFilePath must not be null");
        this.keyStoreType = Objects.requireNonNull(keyStoreType, "keyStoreType must not be null");
        Objects.requireNonNull(keyStorePassword, "keyStorePassword must not be null");

        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("keyStorePassword cannot be blank");
        }

        this.keyStorePassword = keyStorePassword;
        this.javaKeyStore = loadKeyStore();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Path keyStoreFilePath;
        private KeyStoreType keyStoreType;
        private String keyStorePassword;

        public Builder keyStoreFilePath(Path keyStoreFilePath) {
            this.keyStoreFilePath = keyStoreFilePath;
            return this;
        }

        public Builder keyStoreType(KeyStoreType keyStoreType) {
            this.keyStoreType = keyStoreType;
            return this;
        }

        public Builder keyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
            return this;
        }

        public KeyStore build() throws KeyStoreException {
            return new KeyStore(keyStoreFilePath, keyStoreType, keyStorePassword);
        }
    }

    private java.security.KeyStore loadKeyStore() throws KeyStoreException {
        try {
            return loadKeyStoreFromFile();
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("KeyStore cannot be created", e);
        }
    }

    private java.security.KeyStore loadKeyStoreFromFile()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

        // Initialize KeyStore
        if (Files.exists(keyStoreFilePath)) {
            try (final InputStream inputStream = Files.newInputStream(keyStoreFilePath)) {
                keyStore.load(inputStream, keyStorePassword.toCharArray());
            } catch (IOException e) {
                throw new KeyStoreException("KeyStore cannot be opened", e);
            }
        } else {
            // Create a new KeyStore if it doesn't exist
            keyStore.load(null, keyStorePassword.toCharArray());
        }
        return keyStore;
    }

    /**
     * Store a private key and X.509 certificate chain in a Java KeyStore
     *
     * @param keyEntry contains the alias, privateKey, chain, privateKey password
     */
    void storePrivateKeyEntry(final PrivateKeyEntry keyEntry) throws KeyStoreException {
        update(candidate -> candidate.setKeyEntry(
                keyEntry.getAlias(),
                keyEntry.getPrivateKey(),
                keyEntry.getPassword().toCharArray(),
                keyEntry.getCertificateChain()
        ));
    }

    /**
     * Store an Authority Entry in the KeyStore.
     */
    void storeAuthorityEntry(final AuthorityEntry authorityEntry) throws KeyStoreException {
        update(candidate -> candidate.setCertificateEntry(
                authorityEntry.getAlias(),
                authorityEntry.getCertificate()
        ));
    }

    /**
     * Replaces all helper-managed authorities with the complete bundle set, including removing absent trust domains.
     * Changes are staged in a separate KeyStore and flushed once before becoming the live in-memory store.
     * File writes remain in place, so an I/O failure can still leave a partial file.
     */
    void replaceAuthorityEntries(final List<AuthorityEntry> authorityEntries) throws KeyStoreException {
        update(replacement -> setAuthorityEntries(replacement, authorityEntries));
    }

    private void setAuthorityEntries(final java.security.KeyStore replacement,
                                     final List<AuthorityEntry> authorityEntries) throws KeyStoreException {
        List<String> aliasesToDelete = new ArrayList<>();
        Enumeration<String> aliases = replacement.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (replacement.isCertificateEntry(alias) && isAuthorityAlias(alias)) {
                aliasesToDelete.add(alias);
            }
        }

        for (String alias : aliasesToDelete) {
            replacement.deleteEntry(alias);
        }

        for (AuthorityEntry authorityEntry : authorityEntries) {
            replacement.setCertificateEntry(
                    authorityEntry.getAlias(),
                    authorityEntry.getCertificate()
            );
        }
    }

    /**
     * A change applied to a candidate copy of the live KeyStore.
     */
    @FunctionalInterface
    private interface Change {
        void applyTo(java.security.KeyStore candidate) throws KeyStoreException;
    }

    /**
     * Applies a change to a copy of the live KeyStore, writes the copy to disk and only then makes it the live
     * in-memory store. If applying the change or writing the file fails, the live store keeps its previous entries, so
     * a later successful write never persists a failed update.
     */
    private void update(final Change change) throws KeyStoreException {
        java.security.KeyStore candidate = copyKeyStore();
        change.applyTo(candidate);
        flush(candidate);
        javaKeyStore = candidate;
    }

    private java.security.KeyStore copyKeyStore() throws KeyStoreException {
        try {
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            javaKeyStore.store(content, keyStorePassword.toCharArray());
            java.security.KeyStore copy = java.security.KeyStore.getInstance(javaKeyStore.getType(), javaKeyStore.getProvider());
            copy.load(new ByteArrayInputStream(content.toByteArray()), keyStorePassword.toCharArray());
            return copy;
        } catch (IOException | GeneralSecurityException e) {
            throw new KeyStoreException("KeyStore cannot be copied", e);
        }
    }

    private boolean isAuthorityAlias(final String alias) {
        int separator = alias.lastIndexOf('.');
        if (separator <= 0 || separator == alias.length() - 1) {
            return false;
        }

        for (int i = separator + 1; i < alias.length(); i++) {
            char character = alias.charAt(i);
            if (character < '0' || character > '9') {
                return false;
            }
        }
        try {
            String trustDomain = alias.substring(0, separator);
            return TrustDomain.parse(trustDomain).getName().equals(trustDomain);
        } catch (InvalidSpiffeIdException | IllegalArgumentException e) {
            return false;
        }
    }

    // Flush KeyStore to disk, to the configured keyStoreFilePath. The KeyStore is serialized to memory before the file
    // is opened, so a store or encoding failure leaves the existing file as it was. An I/O failure while writing the
    // bytes can still leave a partial file.
    private void flush(final java.security.KeyStore keyStore) throws KeyStoreException {
        try {
            KeyStoreFileWriter.write(keyStoreFilePath, outputStream -> keyStore.store(outputStream, keyStorePassword.toCharArray()));
        } catch (KeyStoreException e) {
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            throw new KeyStoreException(e);
        }
    }
}
