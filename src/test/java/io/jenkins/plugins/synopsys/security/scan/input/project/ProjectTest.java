package io.jenkins.plugins.synopsys.security.scan.input.project;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class ProjectTest {

    @Test
    void testGetSetDirectory() {
        Project project = new Project();
        project.setDirectory("test_directory");
        assertEquals("test_directory", project.getDirectory());
    }

    @Test
    void testGetSetSource() {
        Project project = new Project();
        Source source = new Source();
        source.setArchive("test_archive");
        source.setPreserveSymLinks(true);
        source.setExcludes(Arrays.asList("exclude1", "exclude2"));
        project.setSource(source);

        assertEquals("test_archive", project.getSource().getArchive());
        assertTrue(project.getSource().getPreserveSymLinks());
        assertEquals(Arrays.asList("exclude1", "exclude2"), project.getSource().getExcludes());
    }

    @Test
    void testSerialization() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        Source source = new Source();
        source.setArchive("test_archive");
        source.setPreserveSymLinks(true);
        source.setExcludes(Arrays.asList("exclude1", "exclude2"));

        Project project = new Project();
        project.setDirectory("test_directory");
        project.setSource(source);

        String json = mapper.writeValueAsString(project);

        Project deserializedProject = mapper.readValue(json, Project.class);

        assertEquals(project, deserializedProject);
    }

    @Test
    void testDeserialization() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();

        String json = "{\n" + "  \"directory\" : \"test_directory\",\n"
                + "  \"source\" : {\n"
                + "    \"archive\" : \"test_archive\",\n"
                + "    \"preserveSymLinks\" : true,\n"
                + "    \"excludes\" : [ \"exclude1\", \"exclude2\" ]\n"
                + "  }\n"
                + "}";

        Project project = mapper.readValue(json, Project.class);

        assertEquals("test_directory", project.getDirectory());
        assertEquals("test_archive", project.getSource().getArchive());
        assertTrue(project.getSource().getPreserveSymLinks());
        assertEquals(Arrays.asList("exclude1", "exclude2"), project.getSource().getExcludes());
    }
}
