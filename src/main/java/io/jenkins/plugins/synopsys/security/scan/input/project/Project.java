package io.jenkins.plugins.synopsys.security.scan.input.project;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

public class Project {
    @JsonProperty("directory")
    private String directory;

    @JsonProperty("source")
    private Source source;

    public String getDirectory() {
        return directory;
    }

    public void setDirectory(String directory) {
        this.directory = directory;
    }

    public Source getSource() {
        return source;
    }

    public void setSource(Source source) {
        this.source = source;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Project project = (Project) o;
        return Objects.equals(directory, project.directory) && Objects.equals(source, project.source);
    }

    @Override
    public int hashCode() {
        return Objects.hash(directory, source);
    }
}
