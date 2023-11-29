package io.jenkins.plugins.synopsys.security.scan.input.report;

import com.fasterxml.jackson.annotation.JsonProperty;

public class File {
    @JsonProperty("path")
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
}
