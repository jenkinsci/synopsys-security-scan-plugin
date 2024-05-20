package io.jenkins.plugins.synopsys.security.scan.input.project;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Source {
    @JsonProperty("archive")
    private String archive;

    @JsonProperty("preserveSymLinks")
    private Boolean preserveSymLinks;

    @JsonProperty("excludes")
    private List<String> excludes;

    public String getArchive() {
        return archive;
    }

    public void setArchive(String archive) {
        this.archive = archive;
    }

    public Boolean getPreserveSymLinks() {
        return preserveSymLinks;
    }

    public void setPreserveSymLinks(Boolean preserveSymLinks) {
        this.preserveSymLinks = preserveSymLinks;
    }

    public List<String> getExcludes() {
        return excludes;
    }

    public void setExcludes(List<String> excludes) {
        this.excludes = excludes;
    }
}
