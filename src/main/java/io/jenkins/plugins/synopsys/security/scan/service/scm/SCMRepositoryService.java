package io.jenkins.plugins.synopsys.security.scan.service.scm;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.github.GithubRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab.GitlabRepositoryService;
import java.util.Map;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMSource;
import jenkins.scm.api.SCMSourceOwner;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;

public class SCMRepositoryService {
    private final TaskListener listener;
    private final EnvVars envVars;
    private final LoggerWrapper logger;

    public SCMRepositoryService(TaskListener listener, EnvVars envVars) {
        this.listener = listener;
        this.envVars = envVars;
        this.logger = new LoggerWrapper(listener);
    }

    public Object fetchSCMRepositoryDetails(
            Map<String, Boolean> installedBranchSourceDependencies,
            Map<String, Object> scanParameters,
            boolean isFixPrOrPrComment)
            throws PluginExceptionHandler {

        String pullRequestNumber = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        Integer projectRepositoryPullNumber = pullRequestNumber != null ? Integer.parseInt(pullRequestNumber) : null;

        LoggerWrapper logger = new LoggerWrapper(listener);
        if (isFixPrOrPrComment && projectRepositoryPullNumber == null) {
            String productName = (String) scanParameters.get(ApplicationConstants.PRODUCT_KEY);
            if (productName.equalsIgnoreCase("BLACKDUCK")) {
                logger.info(ApplicationConstants.BLACKDUCK_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            } else if (productName.equalsIgnoreCase("COVERITY")) {
                logger.info(ApplicationConstants.COVERITY_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            } else if (productName.equalsIgnoreCase("POLARIS")) {
                logger.info(ApplicationConstants.POLARIS_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }

        SCMSource scmSource = findSCMSource();
        if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof BitbucketSCMSource) {
            BitbucketRepositoryService bitbucketRepositoryService = new BitbucketRepositoryService(listener);
            BitbucketSCMSource bitbucketSCMSource = (BitbucketSCMSource) scmSource;
            return bitbucketRepositoryService.fetchBitbucketRepositoryDetails(
                    scanParameters, bitbucketSCMSource, projectRepositoryPullNumber, isFixPrOrPrComment);
        } else if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitHubSCMSource) {
            GithubRepositoryService githubRepositoryService = new GithubRepositoryService(listener);
            GitHubSCMSource gitHubSCMSource = (GitHubSCMSource) scmSource;

            String repositoryOwner = gitHubSCMSource.getRepoOwner();
            String repositoryName = gitHubSCMSource.getRepository();
            String branchName = envVars.get(ApplicationConstants.BRANCH_NAME);
            String apiUri = gitHubSCMSource.getApiUri();

            return githubRepositoryService.createGithubObject(
                    scanParameters,
                    repositoryName,
                    repositoryOwner,
                    projectRepositoryPullNumber,
                    branchName,
                    isFixPrOrPrComment,
                    apiUri);
        } else if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitLabSCMSource) {
            GitlabRepositoryService gitlabRepositoryService = new GitlabRepositoryService(listener);
            GitLabSCMSource gitLabSCMSource = (GitLabSCMSource) scmSource;

            String repositoryUrl = gitLabSCMSource.getHttpRemote();
            String branchName = envVars.get(ApplicationConstants.BRANCH_NAME);
            String repositoryName = gitLabSCMSource.getProjectPath();

            return gitlabRepositoryService.createGitlabObject(
                    scanParameters,
                    repositoryName,
                    projectRepositoryPullNumber,
                    branchName,
                    repositoryUrl,
                    isFixPrOrPrComment);
        }
        return null;
    }

    public SCMSource findSCMSource() {
        String jobName = envVars.get(ApplicationConstants.ENV_JOB_NAME_KEY);
        jobName = jobName.substring(0, jobName.indexOf("/"));
        logger.info("Jenkins Job name: " + jobName);

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
