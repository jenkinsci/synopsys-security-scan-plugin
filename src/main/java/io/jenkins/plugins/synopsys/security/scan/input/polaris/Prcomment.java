package io.jenkins.plugins.synopsys.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Prcomment {
    @JsonProperty("enabled")
    private Boolean enabled;

    @JsonProperty("severities")
    private List<String> severities;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getSeverities() {
        return severities;
    }

    public void setSeverities(List<String> severities) {
        this.severities = severities;
    }
}
