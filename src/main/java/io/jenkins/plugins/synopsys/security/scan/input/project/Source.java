package io.jenkins.plugins.synopsys.security.scan.input.project;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Source source = (Source) o;
        return Objects.equals(archive, source.archive)
                && Objects.equals(preserveSymLinks, source.preserveSymLinks)
                && Objects.equals(excludes, source.excludes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(archive, preserveSymLinks, excludes);
    }
}
