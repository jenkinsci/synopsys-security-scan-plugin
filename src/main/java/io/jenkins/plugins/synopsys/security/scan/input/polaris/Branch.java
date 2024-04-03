package io.jenkins.plugins.synopsys.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Branch {
    @JsonProperty("name")
    private String name;

    @JsonProperty("parent")
    private Parent parent;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Parent getParent() {
        return parent;
    }

    public void setParent(Parent parent) {
        this.parent = parent;
    }
}
