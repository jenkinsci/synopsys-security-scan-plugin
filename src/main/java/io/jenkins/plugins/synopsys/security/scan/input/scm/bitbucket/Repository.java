package io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.scm.common.Branch;
import io.jenkins.plugins.synopsys.security.scan.input.scm.common.Pull;

public class Repository {
    @JsonProperty("pull")
    private Pull pull;

    @JsonProperty("name")
    private String name;

    @JsonProperty("branch")
    private Branch branch;

    public Repository() {
        branch = new Branch();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Pull getPull() {
        return pull;
    }

    public void setPull(Pull pull) {
        this.pull = pull;
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }
}
