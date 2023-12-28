package io.jenkins.plugins.synopsys.security.scan.input.scm.github;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Repository {
    private String name;

    @JsonProperty("owner")
    private Owner owner;

    @JsonProperty("pull")
    private Pull pull;

    @JsonProperty("branch")
    private Branch branch;

    public Repository() {
        owner = new Owner();
        pull = new Pull();
        branch = new Branch();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Owner getOwner() {
        return owner;
    }

    public void setOwner(Owner owner) {
        this.owner = owner;
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
