package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;

public class User {
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("token")
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
