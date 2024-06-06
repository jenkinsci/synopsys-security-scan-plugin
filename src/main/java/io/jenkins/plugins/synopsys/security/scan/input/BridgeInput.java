package io.jenkins.plugins.synopsys.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import io.jenkins.plugins.synopsys.security.scan.input.report.Reports;
import io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Github;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;

public class BridgeInput {
    @JsonProperty("blackduck")
    private BlackDuck blackDuck;

    @JsonProperty("coverity")
    private Coverity coverity;

    @JsonProperty("polaris")
    private Polaris polaris;

    @JsonProperty("project")
    private Project project;

    @JsonProperty("bitbucket")
    private Bitbucket bitbucket;

    @JsonProperty("github")
    private Github github;

    @JsonProperty("gitlab")
    private Gitlab gitlab;

    @JsonProperty("network")
    private NetworkAirGap networkAirGap;

    @JsonProperty("reports")
    private Reports reports;

    public Reports getReports() {
        return reports;
    }

    public void setReports(Reports reports) {
        this.reports = reports;
    }

    public BlackDuck getBlackDuck() {
        return blackDuck;
    }

    public void setBlackDuck(BlackDuck blackDuck) {
        this.blackDuck = blackDuck;
    }

    public Coverity getCoverity() {
        return coverity;
    }

    public void setCoverity(Coverity coverity) {
        this.coverity = coverity;
    }

    public Polaris getPolaris() {
        return polaris;
    }

    public void setPolaris(Polaris polaris) {
        this.polaris = polaris;
    }

    public Bitbucket getBitbucket() {
        return bitbucket;
    }

    public void setBitbucket(Bitbucket bitbucket) {
        this.bitbucket = bitbucket;
    }

    public NetworkAirGap getNetworkAirGap() {
        return networkAirGap;
    }

    public void setNetworkAirGap(final NetworkAirGap networkAirGap) {
        this.networkAirGap = networkAirGap;
    }

    public Github getGithub() {
        return github;
    }

    public void setGithub(Github github) {
        this.github = github;
    }

    public Gitlab getGitlab() {
        return gitlab;
    }

    public void setGitlab(Gitlab gitlab) {
        this.gitlab = gitlab;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }
}
