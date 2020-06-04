package spiffe.helper.keystore;

import lombok.Builder;
import lombok.NonNull;
import lombok.val;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Represents a Java KeyStore, provides some functions
 * to store a private key, a X.509 certificate chain, and X.509 bundles.
 * Package private, to be used by the KeyStoreHelper.
 */
class KeyStore {

    private final Path keyStoreFilePath;
    private final KeyStoreType keyStoreType;
    private final String keyStorePassword;

    private final java.security.KeyStore javaKeyStore;
    private final File keyStoreFile;

    @Builder
    KeyStore(
            @NonNull final Path keyStoreFilePath,
            @NonNull final KeyStoreType keyStoreType,
            @NonNull final String keyStorePassword) throws KeyStoreException {
        this.keyStoreFilePath = keyStoreFilePath;
        this.keyStoreType = keyStoreType;

        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("keyStorePassword cannot be blank");
        }
        this.keyStorePassword = keyStorePassword;
        this.keyStoreFile = new File(keyStoreFilePath.toUri());
        this.javaKeyStore = loadKeyStore(keyStoreFile);
    }

    private java.security.KeyStore loadKeyStore(final File keyStoreFile) throws KeyStoreException {
        try {
            val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

            // Initialize KeyStore
            if (Files.exists(keyStoreFilePath)) {
                try (final FileInputStream fileInputStream = new FileInputStream(keyStoreFile)) {
                    keyStore.load(fileInputStream, keyStorePassword.toCharArray());
                }
            } else {
                //create new keyStore
                keyStore.load(null, keyStorePassword.toCharArray());
            }
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }
    }


    /**
     * Store a private key and X.509 certificate chain in a Java KeyStore
     *
     * @param keyEntry contains the alias, privateKey, chain, privateKey password
     */
    void storePrivateKeyEntry(final PrivateKeyEntry keyEntry) throws KeyStoreException {
        // Store PrivateKey Entry in KeyStore
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
    void storeAuthorityEntry(AuthorityEntry authorityEntry) throws KeyStoreException {
        // Store Bundle Entry in KeyStore
        this.javaKeyStore.setCertificateEntry(
                authorityEntry.getAlias(),
                authorityEntry.getCertificate()
        );
        this.flush();
    }

    // Flush KeyStore to disk, to the configured keyStoreFilePath
    private void flush() throws KeyStoreException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(keyStoreFile)){
            javaKeyStore.store(fileOutputStream, keyStorePassword.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }
    }
}
