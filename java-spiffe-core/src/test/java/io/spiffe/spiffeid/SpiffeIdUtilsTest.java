package io.spiffe.spiffeid;

import lombok.val;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeIdUtilsTest {

    @Test
    void getSpiffeIdSetFromFile() throws URISyntaxException {
        Path path = Paths.get(toUri("testdata/spiffeid/spiffeIds.txt"));

        try {
            Set<SpiffeId> spiffeIdSet = SpiffeIdUtils.getSpiffeIdSetFromFile(path);
            assertNotNull(spiffeIdSet);
            assertEquals(3, spiffeIdSet.size());
            assertTrue(spiffeIdSet.contains(SpiffeId.parse("spiffe://example.org/workload1")));
            assertTrue(spiffeIdSet.contains(SpiffeId.parse("spiffe://example.org/workload2")));
            assertTrue(spiffeIdSet.contains(SpiffeId.parse("spiffe://example2.org/workload1")));
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void getSpiffeIdSetFromNonExistenFile_throwsException() throws IOException {
        Path path = Paths.get("testdata/spiffeid/non-existent-file");

        try {
            SpiffeIdUtils.getSpiffeIdSetFromFile(path);
            fail("should have thrown exception");
        } catch (NoSuchFileException e) {
            assertEquals("testdata/spiffeid/non-existent-file", e.getMessage());
        }
    }

    @Test
    void toSetOfSpiffeIds() {
        val spiffeIdsAsString = " spiffe://example.org/workload1, spiffe://example.org/workload2 ";
        val spiffeIdSet = SpiffeIdUtils.toSetOfSpiffeIds(spiffeIdsAsString, ',');

        assertNotNull(spiffeIdSet);
        assertEquals(2, spiffeIdSet.size());
        assertTrue(spiffeIdSet.contains(SpiffeId.parse("spiffe://example.org/workload1")));
        assertTrue(spiffeIdSet.contains(SpiffeId.parse("spiffe://example.org/workload2")));
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}