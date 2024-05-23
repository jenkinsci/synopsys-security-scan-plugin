package io.jenkins.plugins.synopsys.security.scan.input.project;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SourceTest {

    @Test
    public void testGetSetArchive() {
        Source source = new Source();
        source.setArchive("test_archive");
        assertEquals("test_archive", source.getArchive());
    }

    @Test
    public void testGetSetPreserveSymLinks() {
        Source source = new Source();
        source.setPreserveSymLinks(true);
        assertTrue(source.getPreserveSymLinks());
        source.setPreserveSymLinks(false);
        assertFalse(source.getPreserveSymLinks());
    }

    @Test
    public void testGetSetExcludes() {
        Source source = new Source();
        source.setExcludes(Arrays.asList("exclude1", "exclude2"));
        assertEquals(Arrays.asList("exclude1", "exclude2"), source.getExcludes());
    }
}
