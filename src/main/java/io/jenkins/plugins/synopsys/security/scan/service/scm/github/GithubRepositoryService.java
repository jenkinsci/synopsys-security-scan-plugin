package io.jenkins.plugins.synopsys.security.scan.service.scm.github;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Github;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

public class GithubRepositoryService {
    private final LoggerWrapper logger;
    private String GITHUB_CLOUD_HOST_URL = "https://github.com/";
    private String GITHUB_CLOUD_API_URI = "https://api.github.com";
    private String INVALID_GITHUB_REPO_URL = "Invalid Github repository URL";

    public GithubRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Github createGithubObject(
            Map<String, Object> scanParameters,
            String repositoryName,
            String repositoryOwner,
            Integer projectRepositoryPullNumber,
            String branchName,
            boolean isFixPrOrPrComment,
            String githubApiUri)
            throws PluginExceptionHandler {
        String githubToken = (String) scanParameters.get(ApplicationConstants.GITHUB_TOKEN_KEY);

        if (isFixPrOrPrComment && Utility.isStringNullOrBlank(githubToken)) {
            logger.error(LogMessages.NO_GITHUB_TOKEN_FOUND);
            throw new PluginExceptionHandler(LogMessages.NO_GITHUB_TOKEN_FOUND);
        }

        Github github = new Github();

        github.getUser().setToken(githubToken);
        github.getRepository().setName(repositoryName);
        github.getRepository().getOwner().setName(repositoryOwner);
        github.getRepository().getPull().setNumber(projectRepositoryPullNumber);
        github.getRepository().getBranch().setName(branchName);

        String githubHostUrl = extractGitHubHost(githubApiUri);
        logger.info("githubHostUrl: " + githubHostUrl);

        if (githubHostUrl.equals(INVALID_GITHUB_REPO_URL)) {
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

    public String extractGitHubHost(String githubApiUri) {
        try {
            return GITHUB_CLOUD_API_URI.equals(githubApiUri)
                    ? GITHUB_CLOUD_HOST_URL
                    : String.format("%s", StringUtils.removeEnd(githubApiUri, "api/v3"));
        } catch (Exception e) {
            return INVALID_GITHUB_REPO_URL;
        }
    }
}
