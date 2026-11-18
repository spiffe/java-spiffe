package io.spiffe.helper.keystore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class AtomicFileWriterTest {

    private static final byte[] OLD_CONTENT = "old content".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NEW_CONTENT = "new content".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    @Test
    void write_createsFile() throws Exception {
        Path target = dir.resolve("keystore.p12");

        AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_replacesExistingFile() throws Exception {
        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);

        AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_missingParentDirectory_namesTheTarget() {
        Path target = dir.resolve("missing").resolve("keystore.p12");

        NoSuchFileException e = assertThrows(NoSuchFileException.class,
                () -> AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT)));

        assertEquals(target.toString(), e.getMessage());
        assertTrue(Files.notExists(dir.resolve("missing")));
    }

    @Test
    void write_ioFailure_keepsExistingFile() throws Exception {
        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        IOException failure = new IOException("disk full");

        IOException thrown = assertThrows(IOException.class, () -> AtomicFileWriter.write(target, out -> {
            out.write(NEW_CONTENT, 0, 3);
            throw failure;
        }));

        assertSame(failure, thrown);
        assertArrayEquals(OLD_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_serializationFailure_keepsExistingFile() throws Exception {
        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        KeyStoreException failure = new KeyStoreException("cannot encode entry");

        GeneralSecurityException thrown = assertThrows(GeneralSecurityException.class, () -> AtomicFileWriter.write(target, out -> {
            out.write(NEW_CONTENT, 0, 3);
            throw failure;
        }));

        assertSame(failure, thrown);
        assertArrayEquals(OLD_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_failureOnNewFile_leavesNothingBehind() throws Exception {
        Path target = dir.resolve("keystore.p12");

        assertThrows(IOException.class, () -> AtomicFileWriter.write(target, out -> {
            throw new IOException("disk full");
        }));

        assertEquals(Collections.emptyList(), listFiles());
    }

    @Test
    void write_preservesPosixPermissions() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-r-----");
        Files.setPosixFilePermissions(target, permissions);

        AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertEquals(permissions, Files.getPosixFilePermissions(target));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
    }

    @Test
    void write_readOnlyFile_keepsItReadOnly() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("r--------");
        Files.setPosixFilePermissions(target, permissions);

        AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertEquals(permissions, Files.getPosixFilePermissions(target));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
    }

    @Test
    void write_symbolicLink_replacesLinkTarget() throws Exception {
        Path realFile = Files.write(dir.resolve("real.p12"), OLD_CONTENT);
        Path link = dir.resolve("link.p12");
        try {
            Files.createSymbolicLink(link, realFile);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symbolic links are not supported: " + e);
        }

        AtomicFileWriter.write(link, out -> out.write(NEW_CONTENT));

        assertTrue(Files.isSymbolicLink(link));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(realFile));
    }

    @Test
    void write_danglingRelativeSymbolicLink_createsLinkTargetAndKeepsLink() throws Exception {
        Path link = dir.resolve("link.p12");
        try {
            Files.createSymbolicLink(link, Paths.get("real.p12"));
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symbolic links are not supported: " + e);
        }

        AtomicFileWriter.write(link, out -> out.write(NEW_CONTENT));

        assertTrue(Files.isSymbolicLink(link));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(dir.resolve("real.p12")));
    }

    @Test
    void write_newPosixFileDoesNotLeaveGroupOrOtherAccessOnTemporaryFile() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));

        AtomicFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target));
    }

    private List<Path> listFiles() throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.sorted().collect(Collectors.toList());
        }
    }
}
