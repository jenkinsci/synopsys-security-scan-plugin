package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.scm.common.Branch;
import io.jenkins.plugins.synopsys.security.scan.input.scm.common.Pull;

public class Repository {
    @JsonProperty("branch")
    private Branch branch;

    @JsonProperty("pull")
    private Pull pull;

    @JsonProperty("name")
    private String name;

    public Repository() {
        branch = new Branch();
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }

    public Pull getPull() {
        return pull;
    }

    public void setPull(Pull pull) {
        this.pull = pull;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
