package io.jenkins.plugins.synopsys.security.scan.service.scm.github;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.github.Github;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

public class GithubRepositoryService {
    private final LoggerWrapper logger;
    private final String GITHUB_CLOUD_HOST_URL = "https://github.com/";
    private final String INVALID_GITHUB_REPO_URL = "Invalid Github repository URL";
    public GithubRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Github createGithubObject(
            Map<String, Object> scanParameters,
            String repositoryName,
            String repositoryOwner,
            Integer projectRepositoryPullNumber,
            String branchName,
            String repositoryUrl,
            boolean isFixPrOrPrComment)
            throws PluginExceptionHandler {
        String githubToken = (String) scanParameters.get(ApplicationConstants.GITHUB_TOKEN_KEY);

        if (isFixPrOrPrComment && Utility.isStringNullOrBlank(githubToken)) {
            logger.error(LogMessages.NO_GITHUB_TOKEN_FOUND);
            throw new PluginExceptionHandler(LogMessages.NO_GITHUB_TOKEN_FOUND);
        }

        logger.info("Github token: ========= " + githubToken);


        Github github = new Github();

        github.getUser().setToken(githubToken);
        github.getRepository().setName(repositoryName);
        github.getRepository().getOwner().setName(repositoryOwner);
        github.getRepository().getPull().setNumber(projectRepositoryPullNumber);
        github.getRepository().getBranch().setName(branchName);

        String githubHostUrl = extractGitHubHost(repositoryUrl);
        if(githubHostUrl.equals(INVALID_GITHUB_REPO_URL)) {
            throw new PluginExceptionHandler(INVALID_GITHUB_REPO_URL);
        } else {
            if (githubHostUrl.startsWith(GITHUB_CLOUD_HOST_URL)) {
                github.getHost().setUrl("");
            } else {
                github.getHost().setUrl(githubHostUrl);
            }
        }

        return github;
    }

    public String extractGitHubHost(String url) {
        try {
            URL gitHubUrl = new URL(url);
            int port = gitHubUrl.getPort();
            return String.format("%s://%s%s/", gitHubUrl.getProtocol(), gitHubUrl.getHost(), (port == -1) ? "" : ":" + port);
        } catch (MalformedURLException e) {
            return INVALID_GITHUB_REPO_URL;
        }
    }
}