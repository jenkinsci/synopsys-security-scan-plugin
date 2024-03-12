package io.jenkins.plugins.synopsys.security.scan.input.report;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Issue {
    @JsonProperty("types")
    private List<String> types;

    public List<String> getTypes() {
        return types;
    }

    public void setTypes(List<String> types) {
        this.types = types;
    }
}
