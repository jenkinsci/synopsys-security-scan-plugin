package io.jenkins.plugins.synopsys.security.scan.input.srm;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SRM {
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("url")
    private String url;

    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("apikey")
    private String apikey;

    @JsonProperty("assessment")
    private AssessmentTypes assessmentTypes;

    @JsonProperty("project")
    private Project project;

    @JsonProperty("branch")
    private Branch branch;

    public SRM() {
        assessmentTypes = new AssessmentTypes();
        project = new Project();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getApikey() {
        return apikey;
    }

    public void setApikey(String apikey) {
        this.apikey = apikey;
    }

    public AssessmentTypes getAssessmentTypes() {
        return assessmentTypes;
    }

    public void setAssessmentTypes(AssessmentTypes assessmentTypes) {
        this.assessmentTypes = assessmentTypes;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }
}
