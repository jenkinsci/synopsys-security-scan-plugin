package io.jenkins.plugins.synopsys.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.report.Reports;

public class Polaris {
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("accesstoken")
    private String accessToken;

    @JsonProperty("application")
    private ApplicationName applicationName;

    @JsonProperty("project")
    private ProjectName projectName;

    @JsonProperty("assessment")
    private AssessmentTypes assessmentTypes;

    @JsonProperty("serverUrl")
    private String serverUrl;

    @JsonProperty("triage")
    private String triage;

    @JsonProperty("branch")
    private Branch branch;

    @JsonProperty("test")
    private Test test;

    @JsonProperty("reports")
    private Reports reports;

    public Polaris() {
        applicationName = new ApplicationName();
        projectName = new ProjectName();
        assessmentTypes = new AssessmentTypes();
        branch = new Branch();
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public ApplicationName getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(ApplicationName applicationName) {
        this.applicationName = applicationName;
    }

    public ProjectName getProjectName() {
        return projectName;
    }

    public void setProjectName(ProjectName projectName) {
        this.projectName = projectName;
    }

    public AssessmentTypes getAssessmentTypes() {
        return assessmentTypes;
    }

    public void setAssessmentTypes(AssessmentTypes assessmentTypes) {
        this.assessmentTypes = assessmentTypes;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getTriage() {
        return triage;
    }

    public void setTriage(String triage) {
        this.triage = triage;
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }

    public Test getTest() {
        return test;
    }

    public void setTest(Test test) {
        this.test = test;
    }

    public Reports getReports() {
        return reports;
    }

    public void setReports(Reports reports) {
        this.reports = reports;
    }
}
