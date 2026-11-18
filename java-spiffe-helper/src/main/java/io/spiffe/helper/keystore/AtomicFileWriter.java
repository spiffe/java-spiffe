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
import java.nio.file.attribute.AclFileAttributeView;
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
 * When the destination exists, the temporary file is created readable by its owner only, and gets the destination's
 * group, owner, ACL and permissions before it is moved into place, so key material is never readable by more users
 * than before. If the process is not allowed to reproduce the destination's group, owner or ACL, the destination is
 * overwritten in place instead, which keeps them as they are but is not atomic. When the destination is a symbolic
 * link, including one whose target does not exist yet, the file it points to is replaced or created and the link is
 * kept.
 * <p>
 * Temporary files are named {@code .<file name>.<random>.tmp}. If the process dies while writing, one may be left
 * behind; it is never read, and can be deleted.
 * <p>
 * Package private, to be used by the KeyStore.
 */
final class AtomicFileWriter {

    private static final int MAX_LINK_HOPS = 40;

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
        final Path destination = resolveDestination(target);
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

            if (destinationAttributes != null && !copyAttributes(destinationAttributes, destination, tempFile)) {
                // The replacement would end up with a different group, owner or ACL. Overwrite the destination
                // itself, which keeps all of them.
                overwriteInPlace(tempFile, destination);
                return;
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

        // Readable by the owner only until the group, owner and permissions are set, so the content is never exposed
        // to more users than the destination allows.
        final FileAttribute<Set<PosixFilePermission>> permissions = PosixFilePermissions.asFileAttribute(
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        return FileChannel.open(tempFile, options, permissions);
    }

    /**
     * Gives the temporary file the destination's group, owner, ACL and permissions.
     *
     * @return false if the group, owner or ACL could not be reproduced, in which case the temporary file must not
     * replace the destination
     */
    private static boolean copyAttributes(final PosixFileAttributes source, final Path destination, final Path tempFile) throws IOException {
        final PosixFileAttributeView view = Files.getFileAttributeView(tempFile, PosixFileAttributeView.class);
        final PosixFileAttributes current = view.readAttributes();

        try {
            if (!current.group().equals(source.group())) {
                view.setGroup(source.group());
            }
            if (!current.owner().equals(source.owner())) {
                view.setOwner(source.owner());
            }
            copyAcl(destination, tempFile);
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return false;
        }

        // Set after the owner and group, since changing them can clear the setuid and setgid bits.
        view.setPermissions(source.permissions());
        return true;
    }

    private static void copyAcl(final Path source, final Path target) throws IOException {
        final AclFileAttributeView sourceView = Files.getFileAttributeView(source, AclFileAttributeView.class);
        final AclFileAttributeView targetView = Files.getFileAttributeView(target, AclFileAttributeView.class);
        if (sourceView != null && targetView != null) {
            targetView.setAcl(sourceView.getAcl());
        }
    }

    private static void overwriteInPlace(final Path tempFile, final Path destination) throws IOException {
        try (OutputStream out = Files.newOutputStream(destination)) {
            Files.copy(tempFile, out);
        } finally {
            deleteQuietly(tempFile);
        }
    }

    /**
     * Follows symbolic links to the file that should be replaced. A link whose target does not exist yet resolves to
     * that target, so it gets created and the link is kept.
     */
    private static Path resolveDestination(final Path target) throws IOException {
        if (Files.exists(target)) {
            return target.toRealPath();
        }
        Path current = target.toAbsolutePath();
        for (int hops = 0; Files.isSymbolicLink(current); hops++) {
            if (hops >= MAX_LINK_HOPS) {
                throw new IOException("Too many levels of symbolic links: " + target);
            }
            current = current.resolveSibling(Files.readSymbolicLink(current)).normalize();
            if (Files.exists(current)) {
                return current.toRealPath();
            }
        }
        return current;
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
