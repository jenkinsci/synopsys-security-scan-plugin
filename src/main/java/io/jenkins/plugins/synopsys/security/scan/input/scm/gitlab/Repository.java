package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Repository {
    @JsonProperty("branch")
    private Branch branch;
    @JsonProperty("pull")
    private Pull pull;
    /*@JsonProperty("owner")
    private Owner owner;*/
    @JsonProperty("name")
    private String name;

    public Repository() {
        branch = new Branch();
        pull = new Pull();
//        owner = new Owner();
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

    /*public Owner getOwner() {
        return owner;
    }

    public void setOwner(Owner owner) {
        this.owner = owner;
    }*/
}
