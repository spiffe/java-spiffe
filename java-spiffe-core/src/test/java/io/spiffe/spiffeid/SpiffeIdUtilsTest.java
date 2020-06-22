package io.spiffe.spiffeid;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class SpiffeIdUtilsTest {

    @Test
    void getSpiffeIdListFromFile() throws URISyntaxException {
        Path path = Paths.get(toUri("testdata/spiffeid/spiffeIds.txt"));

        try {
            List<SpiffeId> spiffeIdList = SpiffeIdUtils.getSpiffeIdListFromFile(path);
            assertNotNull(spiffeIdList);
            assertEquals(3, spiffeIdList.size());
            assertEquals(SpiffeId.parse("spiffe://example.org/workload1"), spiffeIdList.get(0));
            assertEquals(SpiffeId.parse("spiffe://example.org/workload2"), spiffeIdList.get(1));
            assertEquals(SpiffeId.parse("spiffe://example2.org/workload1"), spiffeIdList.get(2));
        } catch (IOException e) {
            fail(e);
        }
    }

    @Test
    void getSpiffeIdListFromNonExistenFile_throwsException() throws IOException {
        Path path = Paths.get("testdata/spiffeid/non-existent-file");

        try {
            SpiffeIdUtils.getSpiffeIdListFromFile(path);
            fail("should have thrown exception");
        } catch (NoSuchFileException e) {
            assertEquals("testdata/spiffeid/non-existent-file", e.getMessage());
        }
    }

    @Test
    void toListOfSpiffeIds() {
        String spiffeIdsAsString = " spiffe://example.org/workload1, spiffe://example.org/workload2 ";

        List<SpiffeId> spiffeIdList = SpiffeIdUtils.toListOfSpiffeIds(spiffeIdsAsString, ',');

        assertNotNull(spiffeIdList);
        assertEquals(2, spiffeIdList.size());
        assertEquals(SpiffeId.parse("spiffe://example.org/workload1"), spiffeIdList.get(0));
        assertEquals(SpiffeId.parse("spiffe://example.org/workload2"), spiffeIdList.get(1));
    }

    private URI toUri(String path) throws URISyntaxException {
        return Thread.currentThread().getContextClassLoader().getResource(path).toURI();
    }
}