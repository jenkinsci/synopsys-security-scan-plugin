package io.jenkins.plugins.synopsys.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class AssessmentTypes {
    @JsonProperty("types")
    private List<String> types;

    @JsonProperty("mode")
    private String mode;

    public List<String> getTypes() {
        return types;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public void setTypes(List<String> types) {
        this.types = types;
    }
}
