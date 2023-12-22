package io.jenkins.plugins.synopsys.security.scan.service.scm;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.github.GithubRepositoryService;
import java.util.Map;
import io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab.GitlabRepositoryService;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMSource;
import jenkins.scm.api.SCMSourceOwner;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;

public class SCMRepositoryService {
    private final String gitlabSCMSourceClassName = "io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource";
    private final TaskListener listener;
    private final EnvVars envVars;

    public SCMRepositoryService(TaskListener listener, EnvVars envVars) {
        this.listener = listener;
        this.envVars = envVars;
    }

    public Object fetchSCMRepositoryDetails(Map<String, Object> scanParameters, boolean isFixPrOrPrComment)
            throws PluginExceptionHandler {
        Integer projectRepositoryPullNumber = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null
                ? Integer.parseInt(envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY))
                : null;

        SCMSource scmSource = findSCMSource();
        if(scmSource instanceof GitLabSCMSource) {
            GitLabSCMSource gitLabSCMSource = (GitLabSCMSource) scmSource;
            listener.getLogger().println("====== Repository Name: " + gitLabSCMSource.getProjectName());

        }
        if (scmSource instanceof BitbucketSCMSource) {
            BitbucketRepositoryService bitbucketRepositoryService = new BitbucketRepositoryService(listener);
            BitbucketSCMSource bitbucketSCMSource = (BitbucketSCMSource) scmSource;
            return bitbucketRepositoryService.fetchBitbucketRepositoryDetails(
                    scanParameters, bitbucketSCMSource, projectRepositoryPullNumber, isFixPrOrPrComment);
        } else if (scmSource instanceof GitHubSCMSource) {
            GithubRepositoryService githubRepositoryService = new GithubRepositoryService(listener);
            GitHubSCMSource gitHubSCMSource = (GitHubSCMSource) scmSource;

            String repositoryOwner = gitHubSCMSource.getRepoOwner();
            String repositoryName = gitHubSCMSource.getRepository();
            String branchName = envVars.get(ApplicationConstants.BRANCH_NAME);
            String repositoryUrl = envVars.get(ApplicationConstants.GIT_URL);

            return githubRepositoryService.createGithubObject(
                    scanParameters,
                    repositoryName,
                    repositoryOwner,
                    projectRepositoryPullNumber,
                    branchName,
                    repositoryUrl,
                    isFixPrOrPrComment);
        } else if(scmSource.getClass().getName().equals(gitlabSCMSourceClassName)) {
            GitlabRepositoryService gitlabRepositoryService = new GitlabRepositoryService(listener);
            //api.url if starts with https://gitlab.com then otherwise server-url
            //user.token - scanparametersMap.get(GITLAB_KEY)
            //repository.name - GIT_URL regex
            //repository.branch.name - BRANCH_NAME -> main
            //repository.pull.request
            String repositoryUrl = envVars.get(ApplicationConstants.GIT_URL);
            String branchName = envVars.get(ApplicationConstants.BRANCH_NAME);
//            String repositoryOwner = envVars.

            return gitlabRepositoryService.createGitlabObject(
                    scanParameters,
                    repositoryUrl,
                    projectRepositoryPullNumber,
                    isFixPrOrPrComment);
        }
        return null;
    }

    public SCMSource findSCMSource() {
        String jobName = envVars.get(ApplicationConstants.ENV_JOB_NAME_KEY)
                .substring(0, envVars.get(ApplicationConstants.ENV_JOB_NAME_KEY).indexOf("/"));
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        SCMSourceOwner owner = jenkins != null ? jenkins.getItemByFullName(jobName, SCMSourceOwner.class) : null;
        if (owner != null) {
            for (SCMSource scmSource : owner.getSCMSources()) {
                if (owner.getSCMSource(scmSource.getId()) != null) {
                    return scmSource;
                }
            }
        }
        return null;
    }
}
