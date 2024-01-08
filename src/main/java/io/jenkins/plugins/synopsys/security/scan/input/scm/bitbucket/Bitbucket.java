package io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Bitbucket {
    @JsonProperty("api")
    private Api api;

    @JsonProperty("project")
    private Project project;

    public Bitbucket() {
        api = new Api();
        project = new Project();
    }

    public Api getApi() {
        return api;
    }

    public void setApi(Api api) {
        this.api = api;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }
}
