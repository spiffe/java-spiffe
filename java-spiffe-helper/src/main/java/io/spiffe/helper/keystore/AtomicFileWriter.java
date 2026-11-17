package io.spiffe.helper.keystore;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Replaces a file with new content without leaving it empty or partially written.
 * <p>
 * The content is written to a temporary file next to the destination, synced to disk, and then moved over the
 * destination, atomically where the file system supports it. If writing fails, the destination is left untouched.
 * <p>
 * When the destination exists, the temporary file is created with its POSIX permissions, so key material is never
 * readable by more users than before, and its owner and group are copied where the process is allowed to. When the
 * destination is a symbolic link, the file it points to is replaced and the link is kept.
 * <p>
 * Temporary files are named {@code .<file name>.<random>.tmp}. If the process dies while writing, one may be left
 * behind; it is never read, and can be deleted.
 * <p>
 * Package private, to be used by the KeyStore.
 */
final class AtomicFileWriter {

    private AtomicFileWriter() {
    }

    /**
     * Writes content to an output stream.
     */
    @FunctionalInterface
    interface ContentWriter {
        void writeTo(OutputStream outputStream) throws IOException, GeneralSecurityException;
    }

    /**
     * Replaces the file at {@code target} with the content written by {@code contentWriter}.
     *
     * @param target        the file to create or replace
     * @param contentWriter writes the new content
     * @throws IOException              if the content cannot be written or the file cannot be replaced
     * @throws GeneralSecurityException if thrown by {@code contentWriter}
     */
    static void write(final Path target, final ContentWriter contentWriter) throws IOException, GeneralSecurityException {
        final Path destination = Files.exists(target) ? target.toRealPath() : target.toAbsolutePath();
        final Path parent = destination.getParent();
        if (parent != null && !Files.isDirectory(parent)) {
            // Fail the same way writing to the file directly would, naming the file rather than the temporary one.
            throw new NoSuchFileException(target.toString());
        }
        final Path tempFile = destination.resolveSibling("." + destination.getFileName() + "." + UUID.randomUUID() + ".tmp");
        final PosixFileAttributes destinationAttributes = readPosixAttributes(destination);

        boolean moved = false;
        try {
            try (FileChannel channel = openTempFile(tempFile, destinationAttributes)) {
                final OutputStream outputStream = Channels.newOutputStream(channel);
                contentWriter.writeTo(outputStream);
                outputStream.flush();
                channel.force(true);
            }

            if (destinationAttributes != null) {
                copyPosixAttributes(destinationAttributes, tempFile);
            }

            move(tempFile, destination);
            moved = true;
        } finally {
            if (!moved) {
                deleteQuietly(tempFile);
            }
        }
    }

    private static PosixFileAttributes readPosixAttributes(final Path path) throws IOException {
        if (!Files.exists(path) || Files.getFileAttributeView(path, PosixFileAttributeView.class) == null) {
            return null;
        }
        return Files.readAttributes(path, PosixFileAttributes.class);
    }

    private static FileChannel openTempFile(final Path tempFile, final PosixFileAttributes destinationAttributes) throws IOException {
        final Set<OpenOption> options = new HashSet<>(Arrays.asList(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE));
        if (destinationAttributes == null) {
            return FileChannel.open(tempFile, options);
        }

        // Create the file with the destination's permissions right away, instead of changing them after the content
        // is written, so the content is never readable by more users than the destination is.
        final FileAttribute<Set<PosixFilePermission>> permissions =
                PosixFilePermissions.asFileAttribute(withOwnerWrite(destinationAttributes.permissions()));
        return FileChannel.open(tempFile, options, permissions);
    }

    // The owner needs write permission to fill the temporary file. A read-only destination gets its own
    // permissions back in copyPosixAttributes, before the move.
    private static Set<PosixFilePermission> withOwnerWrite(final Set<PosixFilePermission> permissions) {
        final Set<PosixFilePermission> result = EnumSet.of(PosixFilePermission.OWNER_WRITE);
        result.addAll(permissions);
        return result;
    }

    private static void copyPosixAttributes(final PosixFileAttributes source, final Path target) throws IOException {
        final PosixFileAttributeView view = Files.getFileAttributeView(target, PosixFileAttributeView.class);

        // Changing the owner or group needs privileges the process may not have. The file then keeps the
        // process's owner and group, as a newly created file would.
        try {
            view.setGroup(source.group());
        } catch (IOException | SecurityException e) {
            // keep the default group
        }
        try {
            view.setOwner(source.owner());
        } catch (IOException | SecurityException e) {
            // keep the default owner
        }

        // Set after the owner and group, since changing them can clear the setuid and setgid bits.
        view.setPermissions(source.permissions());
    }

    private static void move(final Path source, final Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteQuietly(final Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            // the temporary file is never read, leaving it behind is harmless
        }
    }
}
