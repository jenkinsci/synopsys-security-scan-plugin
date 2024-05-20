package io.jenkins.plugins.synopsys.security.scan.input.project;

import com.fasterxml.jackson.annotation.JsonProperty;

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
}
