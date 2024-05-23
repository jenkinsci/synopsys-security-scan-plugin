package io.jenkins.plugins.synopsys.security.scan.input.project;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class SourceTest {

    @Test
    void testGetSetArchive() {
        Source source = new Source();
        source.setArchive("test_archive");
        assertEquals("test_archive", source.getArchive());
    }

    @Test
    void testGetSetPreserveSymLinks() {
        Source source = new Source();
        source.setPreserveSymLinks(true);
        assertTrue(source.getPreserveSymLinks());
        source.setPreserveSymLinks(false);
        assertFalse(source.getPreserveSymLinks());
    }

    @Test
    void testGetSetExcludes() {
        Source source = new Source();
        source.setExcludes(Arrays.asList("exclude1", "exclude2"));
        assertEquals(Arrays.asList("exclude1", "exclude2"), source.getExcludes());
    }
}
