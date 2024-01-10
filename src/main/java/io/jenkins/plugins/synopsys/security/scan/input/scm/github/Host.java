package io.jenkins.plugins.synopsys.security.scan.input.scm.github;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Host {
    @JsonProperty("url")
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
