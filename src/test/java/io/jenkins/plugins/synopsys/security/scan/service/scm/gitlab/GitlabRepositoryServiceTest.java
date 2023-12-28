package io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

public class GitlabRepositoryServiceTest {
    private TaskListener listenerMock;
    private GitlabRepositoryService gitlabRepositoryService;
    private final String TEST_REPOSITORY_URL_CLOUD = "https://gitlab.com/user/fake-repo";
    private final String GITLAB_BASE_URL = "https://gitlab.com/";
    private final String TEST_REPOSITORY_URL_ENTERPRISE = "https://custom.gitlabserver.com/user/fake-repo";
    private final String TEST_REPOSITORY_ENTERPRISE_IP = "https://10.0.0.97:8181/user/fake-repo";
    private final String TEST_GITLAB_TOKEN = "MSDFSGOIIEGWGWEGFAKEKEY";
    private final Integer TEST_REPOSITORY_PULL_NUMBER = 7;
    private final String TEST_REPOSITORY_NAME = "fake-repo";
    private final String TEST_REPOSITORY_BRANCH_NAME = "fake-branch";
    private Map<String, Object> scanParametersMap;

    @BeforeEach
    void setUp() {
        listenerMock = Mockito.mock(TaskListener.class);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));

        scanParametersMap = new HashMap<>();
        gitlabRepositoryService = new GitlabRepositoryService(listenerMock);
    }

    @Test
    void cloud_createGitlabObjectTest() throws PluginExceptionHandler {
        scanParametersMap.put(ApplicationConstants.GITLAB_TOKEN_KEY, TEST_GITLAB_TOKEN);

        Gitlab gitlabCloud = gitlabRepositoryService.createGitlabObject(
                scanParametersMap,
                TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_PULL_NUMBER,
                TEST_REPOSITORY_BRANCH_NAME,
                TEST_REPOSITORY_URL_CLOUD,
                true);

        assertEquals(
                gitlabCloud.getUser().getToken(),
                scanParametersMap.get(ApplicationConstants.GITLAB_TOKEN_KEY).toString());
        assertEquals(gitlabCloud.getRepository().getName(), TEST_REPOSITORY_NAME);
        assertEquals(gitlabCloud.getRepository().getPull().getNumber(), TEST_REPOSITORY_PULL_NUMBER);
        assertEquals(gitlabCloud.getRepository().getBranch().getName(), TEST_REPOSITORY_BRANCH_NAME);
        assertEquals(gitlabCloud.getApi().getUrl(), "");
    }

    @Test
    void createGitlabObjectPluginExceptionTest() {
        scanParametersMap.put(ApplicationConstants.PRODUCT_KEY, "blackduck");

        assertThrows(
                PluginExceptionHandler.class,
                () -> gitlabRepositoryService.createGitlabObject(
                        scanParametersMap,
                        TEST_REPOSITORY_NAME,
                        TEST_REPOSITORY_PULL_NUMBER,
                        TEST_REPOSITORY_BRANCH_NAME,
                        TEST_REPOSITORY_URL_CLOUD,
                        true));
    }

    @Test
    void extractGitlabHostTest() {
        String gitlabCloudHost = gitlabRepositoryService.extractGitlabHost(TEST_REPOSITORY_URL_CLOUD);
        String gitlabEnterPriseHost = gitlabRepositoryService.extractGitlabHost(TEST_REPOSITORY_URL_ENTERPRISE);
        String gitlabEnterpriseIpHost = gitlabRepositoryService.extractGitlabHost(TEST_REPOSITORY_ENTERPRISE_IP);
        String invalidGitlabHost = gitlabRepositoryService.extractGitlabHost("invalid.url");

        assertEquals(gitlabCloudHost, "https://gitlab.com/");
        assertEquals(gitlabEnterPriseHost, "https://custom.gitlabserver.com/");
        assertEquals(gitlabEnterpriseIpHost, "https://10.0.0.97:8181/");
        assertEquals(invalidGitlabHost, "Invalid Gitlab repository URL");
    }
}
