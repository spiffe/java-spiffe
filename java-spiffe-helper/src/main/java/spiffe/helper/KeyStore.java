package spiffe.helper;

import lombok.Builder;
import lombok.NonNull;
import lombok.val;

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
 * to store a private key, a X509 certificate chain, and X509 bundles.
 * Package private, to be used by the KeyStoreHelper.
 */
class KeyStore {

    private final Path keyStoreFilePath;
    private final KeyStoreType keyStoreType;
    private final char[] keyStorePassword;

    private java.security.KeyStore javaKeyStore;
    private File keyStoreFile;

    @Builder
    KeyStore(
            @NonNull final Path keyStoreFilePath,
            @NonNull final KeyStoreType keyStoreType,
            @NonNull final char[] keyStorePassword) throws KeyStoreException {
        this.keyStoreFilePath = keyStoreFilePath;
        this.keyStoreType = keyStoreType;
        this.keyStorePassword = keyStorePassword;
        setupKeyStore();
    }

    private void setupKeyStore() throws KeyStoreException {
        this.keyStoreFile = new File(keyStoreFilePath.toUri());
        this.javaKeyStore = loadKeyStore(keyStoreFile);
    }


    private java.security.KeyStore loadKeyStore(final File keyStoreFile) throws KeyStoreException {
        try {
            val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

            // Initialize KeyStore
            if (Files.exists(keyStoreFilePath)) {
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);
            } else {
                //create new keyStore
                keyStore.load(null, keyStorePassword);
            }
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }
    }


    /**
     * Store a private key and X509 certificate chain in a Java KeyStore
     *
     * @param privateKeyEntry contains the alias, privateKey, chain, privateKey password
     */
    void storePrivateKey(final PrivateKeyEntry privateKeyEntry) throws KeyStoreException {
        // Store PrivateKey Entry in KeyStore
        javaKeyStore.setKeyEntry(
                privateKeyEntry.getAlias(),
                privateKeyEntry.getPrivateKey(),
                privateKeyEntry.getPassword(),
                privateKeyEntry.getCertificateChain()
        );

        this.flush();
    }

    /**
     * Store a Bundle Entry in the KeyStore
     */
    void storeBundleEntry(BundleEntry bundleEntry) throws KeyStoreException {
        // Store Bundle Entry in KeyStore
        this.javaKeyStore.setCertificateEntry(
                bundleEntry.getAlias(),
                bundleEntry.getCertificate()
        );
        this.flush();
    }

    // Flush KeyStore to disk, to the configured (@see keyStoreFilePath)
    private void flush() throws KeyStoreException {
        try {
            javaKeyStore.store(new FileOutputStream(keyStoreFile), keyStorePassword);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException(e);
        }
    }
}
