package io.jenkins.plugins.synopsys.security.scan.input.srm;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ProjectName {
    @JsonProperty("name")
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
