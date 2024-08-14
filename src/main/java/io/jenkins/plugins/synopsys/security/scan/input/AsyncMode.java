package io.jenkins.plugins.synopsys.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AsyncMode {
    @JsonProperty("waitForScan")
    private Boolean waitForScan;

    public Boolean isWaitForScan() {
        return waitForScan;
    }

    public void setWaitForScan(Boolean waitForScan) {
        this.waitForScan = waitForScan;
    }
}
