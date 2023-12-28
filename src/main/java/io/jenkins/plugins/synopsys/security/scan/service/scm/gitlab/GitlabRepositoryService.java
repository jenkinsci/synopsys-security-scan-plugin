package io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

public class GitlabRepositoryService {
    private final LoggerWrapper logger;
    private String GITLAB_CLOUD_HOST_URL = "https://gitlab.com/";
    private String INVALID_GITLAB_REPO_URL = "Invalid Gitlab repository URL";

    public GitlabRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Gitlab createGitlabObject(
            Map<String, Object> scanParameters,
            String repositoryUrl,
            String branchName,
            Integer projectRepositoryPullNumber,
            boolean isFixPrOrPrComment) throws PluginExceptionHandler {
        String gitlabToken = (String) scanParameters.get(ApplicationConstants.GITLAB_TOKEN_KEY);

        if (isFixPrOrPrComment && Utility.isStringNullOrBlank(gitlabToken)) {
            logger.error(LogMessages.NO_GITLAB_TOKEN_FOUND);
            throw new PluginExceptionHandler(LogMessages.NO_GITLAB_TOKEN_FOUND);
        }

        Gitlab gitlab = new Gitlab();

        String repositoryName = extractRepositoryNameFromGitUrl(repositoryUrl);
        String gitlabHostUrl = extractGitlabHost(repositoryUrl);

        if (gitlabHostUrl.equals(INVALID_GITLAB_REPO_URL)) {
            throw new PluginExceptionHandler(INVALID_GITLAB_REPO_URL);
        } else {
            if (gitlabHostUrl.startsWith(GITLAB_CLOUD_HOST_URL)) {
                gitlab.getApi().setUrl(GITLAB_CLOUD_HOST_URL);
            } else {
                logger.warn("PR comment for Gitlab is supported for only cloud instances");
            }
        }

        gitlab.getUser().setToken(gitlabToken);
        gitlab.getRepository().setName(repositoryName);
        gitlab.getRepository().getBranch().setName(branchName);
        gitlab.getRepository().getPull().setNumber(projectRepositoryPullNumber);

        return gitlab;
    }

    public String extractRepositoryNameFromGitUrl(String url) {
        try {
            URL gitlabUrl = new URL(url);
            String path = gitlabUrl.getPath();
            return path.substring(path.lastIndexOf('/') + 1).replace(".git", "");
        } catch (Exception e) {
            logger.error("Exception occurred while extracting Project Name for Gitlab repository URL");
            return null;
        }
    }

    public String extractGitlabHost(String url) {
        try {
            URL gitlabUrl = new URL(url);
            int port = gitlabUrl.getPort();
            return String.format(
                    "%s://%s%s/", gitlabUrl.getProtocol(), gitlabUrl.getHost(), (port == -1) ? "" : ":" + port);
        } catch (MalformedURLException e) {
            return INVALID_GITLAB_REPO_URL;
        }
    }
}
