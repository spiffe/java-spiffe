package io.spiffe.helper.keystore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Writes a KeyStore file by serializing it to memory first and then writing the bytes into the file in place.
 * <p>
 * If serializing fails, the file is not touched. Writing in place follows symbolic links and keeps the file's owner,
 * group, permissions and ACLs. An I/O error or a crash while the bytes are being written can still leave the file
 * partially written.
 * <p>
 * Package private, to be used by the KeyStore.
 */
final class KeyStoreFileWriter {

    private KeyStoreFileWriter() {
    }

    /**
     * Writes content to an output stream.
     */
    @FunctionalInterface
    interface ContentWriter {
        void writeTo(OutputStream outputStream) throws IOException, GeneralSecurityException;
    }

    /**
     * Serializes the content written by {@code contentWriter} to memory, then writes it to {@code path}, creating the
     * file if it doesn't exist.
     *
     * @param path          the file to write
     * @param contentWriter writes the new content
     * @throws IOException              if thrown by {@code contentWriter} or the file cannot be written
     * @throws GeneralSecurityException if thrown by {@code contentWriter}
     */
    static void write(final Path path, final ContentWriter contentWriter) throws IOException, GeneralSecurityException {
        final ByteArrayOutputStream content = new ByteArrayOutputStream();
        contentWriter.writeTo(content);
        try (OutputStream outputStream = Files.newOutputStream(path)) {
            content.writeTo(outputStream);
        }
    }
}
