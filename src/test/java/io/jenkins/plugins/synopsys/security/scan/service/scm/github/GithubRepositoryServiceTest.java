package io.jenkins.plugins.synopsys.security.scan.service.scm.github;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Github;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Host;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class GithubRepositoryServiceTest {
    private TaskListener listenerMock;
    private GithubRepositoryService githubRepositoryService;
    private final String CLOUD_API_URI = "https://api.github.com";
    private final String ENTERPRISE_API_URI = "https://custom.githubserver.com/api/v3";
    private final String ENTERPRISE_API_URI_WITH_IP = "https://10.0.0.97:8181/api/v3";
    private final String TEST_GITHUB_TOKEN = "MSDFSGOIIEGWGWEGFAKEKEY";
    private final Integer TEST_REPOSITORY_PULL_NUMBER = 7;
    private final String TEST_REPOSITORY_NAME = "TEST_REPO";
    private final String TEST_REPOSITORY_OWNER = "TEST_OWNER";
    private final String TEST_REPOSITORY_BRANCH_NAME = "TEST_BRANCH";
    private Map<String, Object> scanParametersMap;

    @BeforeEach
    void setUp() {
        listenerMock = Mockito.mock(TaskListener.class);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));

        scanParametersMap = new HashMap<>();
        githubRepositoryService = new GithubRepositoryService(listenerMock);
    }

    @Test
    void createGithubObjectTest() throws PluginExceptionHandler {
        scanParametersMap.put(ApplicationConstants.GITHUB_TOKEN_KEY, TEST_GITHUB_TOKEN);

        Github githubCloud = githubRepositoryService.createGithubObject(
                scanParametersMap,
                TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER,
                TEST_REPOSITORY_PULL_NUMBER,
                TEST_REPOSITORY_BRANCH_NAME,
                true,
                CLOUD_API_URI);

        assertEquals(
                githubCloud.getUser().getToken(),
                scanParametersMap.get(ApplicationConstants.GITHUB_TOKEN_KEY).toString());
        assertEquals(githubCloud.getRepository().getName(), TEST_REPOSITORY_NAME);
        assertEquals(githubCloud.getRepository().getOwner().getName(), TEST_REPOSITORY_OWNER);
        assertEquals(githubCloud.getRepository().getPull().getNumber(), TEST_REPOSITORY_PULL_NUMBER);
        assertEquals(githubCloud.getRepository().getBranch().getName(), TEST_REPOSITORY_BRANCH_NAME);

        Github githubEnterprise = githubRepositoryService.createGithubObject(
                scanParametersMap,
                TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER,
                TEST_REPOSITORY_PULL_NUMBER,
                TEST_REPOSITORY_BRANCH_NAME,
                true,
                ENTERPRISE_API_URI);

        assertEquals(
                githubEnterprise.getUser().getToken(),
                scanParametersMap.get(ApplicationConstants.GITHUB_TOKEN_KEY).toString());
        assertEquals(githubEnterprise.getRepository().getName(), TEST_REPOSITORY_NAME);
        assertEquals(githubEnterprise.getRepository().getOwner().getName(), TEST_REPOSITORY_OWNER);
        assertEquals(githubEnterprise.getRepository().getPull().getNumber(), TEST_REPOSITORY_PULL_NUMBER);
        assertEquals(githubEnterprise.getRepository().getBranch().getName(), TEST_REPOSITORY_BRANCH_NAME);
        assertEquals(githubEnterprise.getHost().getUrl(), "https://custom.githubserver.com/");

        Github githubEnterpriseIp = githubRepositoryService.createGithubObject(
                scanParametersMap,
                TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER,
                TEST_REPOSITORY_PULL_NUMBER,
                TEST_REPOSITORY_BRANCH_NAME,
                true,
                ENTERPRISE_API_URI_WITH_IP);

        assertEquals(githubEnterpriseIp.getHost().getUrl(), "https://10.0.0.97:8181/");
    }

    @Test
    void createGithubObjectPluginExceptionTest() throws PluginExceptionHandler {
        scanParametersMap.put(ApplicationConstants.PRODUCT_KEY, "blackduck");

        assertThrows(
                PluginExceptionHandler.class,
                () -> githubRepositoryService.createGithubObject(
                        scanParametersMap,
                        TEST_REPOSITORY_NAME,
                        TEST_REPOSITORY_OWNER,
                        TEST_REPOSITORY_PULL_NUMBER,
                        TEST_REPOSITORY_BRANCH_NAME,
                        true,
                        CLOUD_API_URI));
    }
}
