package io.spiffe.helper.keystore;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
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
    private final java.security.KeyStore javaKeyStore;

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
        javaKeyStore.setKeyEntry(
                keyEntry.getAlias(),
                keyEntry.getPrivateKey(),
                keyEntry.getPassword().toCharArray(),
                keyEntry.getCertificateChain()
        );
        this.flush();
    }

    /**
     * Store an Authority Entry in the KeyStore.
     */
    void storeAuthorityEntry(final AuthorityEntry authorityEntry) throws KeyStoreException {
        this.javaKeyStore.setCertificateEntry(
                authorityEntry.getAlias(),
                authorityEntry.getCertificate()
        );
        this.flush();
    }

    // Flush KeyStore to disk, to the configured keyStoreFilePath
    private void flush() throws KeyStoreException {
        try (OutputStream outputStream = Files.newOutputStream(keyStoreFilePath)) {
            javaKeyStore.store(outputStream, keyStorePassword.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }
    }
}
