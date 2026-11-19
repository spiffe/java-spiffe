package io.spiffe.helper.keystore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.spiffe.utils.TestUtils.toUri;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class KeyStoreFileWriterTest {

    private static final byte[] OLD_CONTENT = "old content".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NEW_CONTENT = "new content".getBytes(StandardCharsets.UTF_8);
    private static final char[] PASSWORD = "password".toCharArray();
    private static final String ALIAS = "bundle";

    @TempDir
    Path dir;

    @Test
    void write_createsFile() throws Exception {
        Path target = dir.resolve("keystore.p12");

        KeyStoreFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_replacesExistingFile() throws Exception {
        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);

        KeyStoreFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
        assertEquals(Collections.singletonList(target), listFiles());
    }

    @Test
    void write_missingParentDirectory_throwsNoSuchFile() {
        Path target = dir.resolve("missing").resolve("keystore.p12");

        assertThrows(NoSuchFileException.class, () -> KeyStoreFileWriter.write(target, out -> out.write(NEW_CONTENT)));

        assertTrue(Files.notExists(dir.resolve("missing")));
    }

    @Test
    void write_serializationFailure_keepsExistingKeyStore_thenUpdates() throws Exception {
        Path target = dir.resolve("keystore.p12");
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(null, PASSWORD);
        KeyStoreFileWriter.write(target, out -> keyStore.store(out, PASSWORD));
        byte[] original = Files.readAllBytes(target);

        keyStore.setCertificateEntry(ALIAS, loadCertificate());
        KeyStoreException failure = new KeyStoreException("cannot encode entry");
        GeneralSecurityException thrown = assertThrows(GeneralSecurityException.class, () -> KeyStoreFileWriter.write(target, out -> {
            keyStore.store(out, PASSWORD);
            throw failure;
        }));

        assertSame(failure, thrown);
        assertArrayEquals(original, Files.readAllBytes(target));
        assertFalse(load(target).containsAlias(ALIAS));

        KeyStoreFileWriter.write(target, out -> keyStore.store(out, PASSWORD));

        assertTrue(load(target).containsAlias(ALIAS));
    }

    @Test
    void write_ioFailureWhileSerializing_keepsExistingFile() throws Exception {
        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        IOException failure = new IOException("encoding failed");

        IOException thrown = assertThrows(IOException.class, () -> KeyStoreFileWriter.write(target, out -> {
            out.write(NEW_CONTENT, 0, 3);
            throw failure;
        }));

        assertSame(failure, thrown);
        assertArrayEquals(OLD_CONTENT, Files.readAllBytes(target));
    }

    @Test
    void write_failureOnNewFile_leavesNothingBehind() throws Exception {
        Path target = dir.resolve("keystore.p12");

        assertThrows(IOException.class, () -> KeyStoreFileWriter.write(target, out -> {
            throw new IOException("encoding failed");
        }));

        assertEquals(Collections.emptyList(), listFiles());
    }

    @Test
    void write_keepsOwnerOnlyPermissions() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        Path target = Files.write(dir.resolve("keystore.p12"), OLD_CONTENT);
        Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
        Files.setPosixFilePermissions(target, permissions);

        KeyStoreFileWriter.write(target, out -> out.write(NEW_CONTENT));

        assertEquals(permissions, Files.getPosixFilePermissions(target));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(target));
    }

    @Test
    void write_symbolicLink_writesLinkTarget() throws Exception {
        Path realFile = Files.write(dir.resolve("real.p12"), OLD_CONTENT);
        Path link = dir.resolve("link.p12");
        createSymbolicLink(link, realFile);

        KeyStoreFileWriter.write(link, out -> out.write(NEW_CONTENT));

        assertTrue(Files.isSymbolicLink(link));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(realFile));
    }

    @Test
    void write_danglingSymbolicLink_createsLinkTargetAndKeepsLink() throws Exception {
        Path link = dir.resolve("link.p12");
        createSymbolicLink(link, Paths.get("real.p12"));

        KeyStoreFileWriter.write(link, out -> out.write(NEW_CONTENT));

        assertTrue(Files.isSymbolicLink(link));
        assertArrayEquals(NEW_CONTENT, Files.readAllBytes(dir.resolve("real.p12")));
    }

    private static void createSymbolicLink(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "symbolic links are not supported: " + e);
        }
    }

    private static Certificate loadCertificate() throws Exception {
        try (InputStream in = Files.newInputStream(Paths.get(toUri("testdata/bundle.pem")))) {
            return CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static java.security.KeyStore load(Path path) throws Exception {
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, PASSWORD);
        }
        return keyStore;
    }

    private List<Path> listFiles() throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.sorted().collect(Collectors.toList());
        }
    }
}
