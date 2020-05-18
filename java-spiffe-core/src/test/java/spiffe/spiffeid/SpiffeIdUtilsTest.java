package spiffe.spiffeid;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class piffeIdUtilsTest {

    @Test
    void getSpiffeIdsFromSystemProperty() {
        System.setProperty("spiffe.property", " spiffe://example.org/workload1, spiffe://example.org/workload2 ");

        List<SpiffeId> spiffeIdList = SpiffeIdUtils.getSpiffeIdsFromSystemProperty("spiffe.property");

        assertNotNull(spiffeIdList);
        assertEquals(2, spiffeIdList.size());
        assertEquals(SpiffeId.parse("spiffe://example.org/workload1"), spiffeIdList.get(0));
        assertEquals(SpiffeId.parse("spiffe://example.org/workload2"), spiffeIdList.get(1));
    }

    @Test
    void getSpiffeIdsFromSystemPropertyThatHasNoValue_returnsEmptyList() {
        System.setProperty("spiffe.property", "");

        List<SpiffeId> spiffeIdList = SpiffeIdUtils.getSpiffeIdsFromSystemProperty("spiffe.property");

        assertNotNull(spiffeIdList);
        assertEquals(0, spiffeIdList.size());
    }

    @Test
    void getSpiffeIdsFromBlankSystemProperty_throwsIllegalArgumentException() {
        try {
            SpiffeIdUtils.getSpiffeIdsFromSystemProperty("");
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }

    @Test
    void getSpiffeIdsFromNullSystemProperty_throwsIllegalArgumentException() {
        try {
            SpiffeIdUtils.getSpiffeIdsFromSystemProperty(null);
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }

    @Test
    void getSpiffeIdsFromSecurityProperty() {
        Security.setProperty("spiffe.property", " spiffe://example.org/workload1, spiffe://example.org/workload2 ");

        List<SpiffeId> spiffeIdList = SpiffeIdUtils.getSpiffeIdsFromSecurityProperty("spiffe.property");

        assertNotNull(spiffeIdList);
        assertEquals(2, spiffeIdList.size());
        assertEquals(SpiffeId.parse("spiffe://example.org/workload1"), spiffeIdList.get(0));
        assertEquals(SpiffeId.parse("spiffe://example.org/workload2"), spiffeIdList.get(1));
    }

    @Test
    void getSpiffeIdsFromSecurityPropertyThatHasNoValue_returnsEmptyList() {
        Security.setProperty("spiffe.property", "");

        List<SpiffeId> spiffeIdList = SpiffeIdUtils.getSpiffeIdsFromSecurityProperty("spiffe.property");

        assertNotNull(spiffeIdList);
        assertEquals(0, spiffeIdList.size());
    }

    @Test
    void getSpiffeIdsFromBlankSecurityProperty_throwsIllegalArgumentException() {
        try {
            SpiffeIdUtils.getSpiffeIdsFromSecurityProperty("");
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }

    @Test
    void getSpiffeIdsFromNullSecurityProperty_throwsIllegalArgumentException() {
        try {
            SpiffeIdUtils.getSpiffeIdsFromSecurityProperty(null);
            fail("should have thrown exception");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }

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

    @Test
    void toListOfSPiffeIds_blankStringParameter() {
        try {
            SpiffeIdUtils.toListOfSpiffeIds("", ',');
        } catch (IllegalArgumentException e) {
            assertEquals("Argument spiffeIds cannot be empty", e.getMessage());
        }
    }

    private URI toUri(String path) throws URISyntaxException {
        return getClass().getClassLoader().getResource(path).toURI();
    }
}