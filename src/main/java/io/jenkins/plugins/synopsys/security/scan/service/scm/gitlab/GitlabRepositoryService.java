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
            String repositoryName,
            Integer projectRepositoryPullNumber,
            String branchName,
            String repositoryUrl,
            boolean isFixPrOrPrComment)
            throws PluginExceptionHandler {
        String gitlabToken = (String) scanParameters.get(ApplicationConstants.GITLAB_TOKEN_KEY);

        if (isFixPrOrPrComment && Utility.isStringNullOrBlank(gitlabToken)) {
            logger.error(LogMessages.NO_GITLAB_TOKEN_FOUND);
            throw new PluginExceptionHandler(LogMessages.NO_GITLAB_TOKEN_FOUND);
        }

        Gitlab gitlab = new Gitlab();

        gitlab.getUser().setToken(gitlabToken);
        gitlab.getRepository().setName(repositoryName);
        gitlab.getRepository().getBranch().setName(branchName);
        gitlab.getRepository().getPull().setNumber(projectRepositoryPullNumber);

        String gitlabHostUrl = extractGitlabHost(repositoryUrl);
        logger.info("gitlabHostUrl: " + gitlabHostUrl);

        if (gitlabHostUrl.equals(INVALID_GITLAB_REPO_URL)) {
            throw new PluginExceptionHandler(INVALID_GITLAB_REPO_URL);
        } else {
            if (gitlabHostUrl.startsWith(GITLAB_CLOUD_HOST_URL)) {
                gitlab.getApi().setUrl("");
            } else {
                gitlab.getApi().setUrl(gitlabHostUrl);
            }
        }

        return gitlab;
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
