package io.jenkins.plugins.synopsys.security.scan.input.srm;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SRM {
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("url")
    private String url;

    @JsonProperty("apikey")
    private String apikey;

    @JsonProperty("assessment")
    private AssessmentTypes assessmentTypes;

    @JsonProperty("project")
    private ProjectName projectName;

    @JsonProperty("branch")
    private Branch branch;

    public SRM() {
        assessmentTypes = new AssessmentTypes();
        projectName = new ProjectName();
        branch = new Branch();
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

    public ProjectName getProjectName() {
        return projectName;
    }

    public void setProjectName(ProjectName projectName) {
        this.projectName = projectName;
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }
}
