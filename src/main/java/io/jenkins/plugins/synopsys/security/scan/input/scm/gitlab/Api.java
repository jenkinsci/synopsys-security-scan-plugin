package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Api {
    @JsonProperty("url")
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
