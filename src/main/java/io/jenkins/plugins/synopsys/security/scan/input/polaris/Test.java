package io.jenkins.plugins.synopsys.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Test {
    @JsonProperty("sca")
    private Sca sca;

    public Test() {
        sca = new Sca();
    }

    public Sca getSca() {
        return sca;
    }

    public void setSca(Sca sca) {
        this.sca = sca;
    }
}