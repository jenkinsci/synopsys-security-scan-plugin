package io.jenkins.plugins.synopsys.security.scan.input.srm;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Branch {
    @JsonProperty("name")
    private String name;

    @JsonProperty("parent")
    private String parent;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getParent() {
        return parent;
    }

    public void setParent(String parent) {
        this.parent = parent;
    }
}
