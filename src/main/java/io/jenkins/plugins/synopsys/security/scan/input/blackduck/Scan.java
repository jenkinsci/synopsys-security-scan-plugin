package io.jenkins.plugins.synopsys.security.scan.input.blackduck;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Scan {
    @JsonProperty("full")
    private Boolean full;

    @JsonProperty("failure")
    private Failure failure;

    public Scan() {
        failure = new Failure();
    }

    public Boolean getFull() {
        return full;
    }

    public void setFull(Boolean full) {
        this.full = full;
    }

    public Failure getFailure() {
        return failure;
    }

    public void setFailure(Failure failure) {
        this.failure = failure;
    }
}
