package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Owner {
    @JsonProperty("name")
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
