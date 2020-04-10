package spiffe.helper;

import lombok.Builder;
import lombok.NonNull;
import lombok.val;
import spiffe.result.Result;

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
 * to store a PrivateKey, Certificate chain and Bundles.
 * Package private, to be used by the KeyStoreHelper.
 */
class KeyStore {

    private final Path keyStoreFilePath;
    private final KeyStoreType keyStoreType;
    private final char[] keyStorePassword;

    private java.security.KeyStore keyStore;
    private File keyStoreFile;

    @Builder
    KeyStore(
            @NonNull final Path keyStoreFilePath,
            @NonNull final KeyStoreType keyStoreType,
            @NonNull final char[] keyStorePassword) {
        this.keyStoreFilePath = keyStoreFilePath;
        this.keyStoreType = keyStoreType;
        this.keyStorePassword = keyStorePassword;
        setupKeyStore();
    }

    private void setupKeyStore() {
        this.keyStoreFile = new File(keyStoreFilePath.toUri());

        val keyStore = loadKeyStore(keyStoreFile);
        if (keyStore.isError()) {
            throw new RuntimeException(keyStore.getError());
        }
        this.keyStore = keyStore.getValue();
    }


    private Result<java.security.KeyStore, Throwable> loadKeyStore(final File keyStoreFile) {
        try {
            val keyStore = java.security.KeyStore.getInstance(keyStoreType.value());

            // Initialize KeyStore
            if (Files.exists(keyStoreFilePath)) {
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);
            } else {
                //create new keyStore
                keyStore.load(null, keyStorePassword);
            }
            return Result.ok(keyStore);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            return Result.error(e);
        }
    }


    /**
     * Store a PrivateKey and Certificate chain in a Java KeyStore
     *
     * @param privateKeyEntry contains the alias, privateKey, chain, privateKey password
     * @return Result of Boolean indicating if it was successful or an Error wrapping an Exception
     */
    Result<Boolean, Throwable> storePrivateKey(final PrivateKeyEntry privateKeyEntry) {
        try {
            // Store PrivateKey Entry in KeyStore
            keyStore.setKeyEntry(
                    privateKeyEntry.getAlias(),
                    privateKeyEntry.getPrivateKey(),
                    privateKeyEntry.getPassword(),
                    privateKeyEntry.getCertificateChain()
            );

            return this.flush();
        } catch (KeyStoreException e) {
            return Result.error(e);
        }
    }

    /**
     * Store a Bundle Entry in the KeyStore
     */
    Result<Boolean, Throwable> storeBundleEntry(BundleEntry bundleEntry) {
        try {
            // Store Bundle Entry in KeyStore
            this.keyStore.setCertificateEntry(
                    bundleEntry.getAlias(),
                    bundleEntry.getCertificate()
            );
            return this.flush();
        } catch (KeyStoreException e) {
            return Result.error(e);
        }
    }

    // Flush KeyStore to disk, to the configured (@see keyStoreFilePath)
    private Result<Boolean, Throwable> flush() {
        try {
            keyStore.store(new FileOutputStream(keyStoreFile), keyStorePassword);
            return Result.ok(true);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            return Result.error(e);
        }
    }
}
