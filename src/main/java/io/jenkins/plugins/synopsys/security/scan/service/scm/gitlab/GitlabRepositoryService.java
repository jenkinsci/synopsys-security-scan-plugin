package io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;

import java.util.Map;

public class GitlabRepositoryService {
    private final LoggerWrapper logger;

    public GitlabRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Gitlab createGitlabObject(
            Map<String, Object> scanParameters,
            String repositoryUrl,
            Integer projectRepositoryPullNumber,
            boolean isFixPrOrPrComment) {

//        String baseUrl =
        return new Gitlab();
    }
}
