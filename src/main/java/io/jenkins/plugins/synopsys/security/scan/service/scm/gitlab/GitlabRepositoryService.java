package io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.scm.common.Pull;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Api;
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
            logger.error("PrComment is set true but no GitLab token found!");
            throw new PluginExceptionHandler(ErrorCode.NO_GITLAB_TOKEN_FOUND);
        }

        Gitlab gitlab = new Gitlab();

        gitlab.getUser().setToken(gitlabToken);
        gitlab.getRepository().setName(repositoryName);
        gitlab.getRepository().getBranch().setName(branchName);

        if (projectRepositoryPullNumber != null) {
            Pull pull = new Pull();
            pull.setNumber(projectRepositoryPullNumber);
            gitlab.getRepository().setPull(pull);
        }

        String gitlabHostUrl = extractGitlabHost(repositoryUrl);

        if (gitlabHostUrl.equals(INVALID_GITLAB_REPO_URL)) {
            logger.error(INVALID_GITLAB_REPO_URL);
            throw new PluginExceptionHandler(ErrorCode.INVALID_GITLAB_URL);
        } else {
            if (!gitlabHostUrl.startsWith(GITLAB_CLOUD_HOST_URL)) {
                gitlab.setApi(new Api());
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
