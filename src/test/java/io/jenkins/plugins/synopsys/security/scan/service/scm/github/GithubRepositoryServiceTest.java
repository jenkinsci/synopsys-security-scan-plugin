package io.jenkins.plugins.synopsys.security.scan.service.scm.github;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.github.Github;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

public class GithubRepositoryServiceTest {
    private TaskListener listenerMock;
    private GithubRepositoryService githubRepositoryService;
    private final String TEST_REPOSITORY_URL_CLOUD = "https://github.com/user/fake-repo";
    private final String TEST_REPOSITORY_URL_ENTERPRISE = "https://custom.githubserver.com/user/fake-repo";
    private final String TEST_REPOSITORY_ENTERPRISE_IP = "https://10.0.0.97:8181/user/fake-repo";
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

        Github githubCloud = githubRepositoryService.createGithubObject(scanParametersMap, TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER, TEST_REPOSITORY_PULL_NUMBER, TEST_REPOSITORY_BRANCH_NAME,
                TEST_REPOSITORY_URL_CLOUD, true);

        assertEquals(githubCloud.getUser().getToken(), scanParametersMap.get(ApplicationConstants.GITHUB_TOKEN_KEY).toString());
        assertEquals(githubCloud.getRepository().getName(), TEST_REPOSITORY_NAME);
        assertEquals(githubCloud.getRepository().getOwner().getName(), TEST_REPOSITORY_OWNER);
        assertEquals(githubCloud.getRepository().getPull().getNumber(), TEST_REPOSITORY_PULL_NUMBER);
        assertEquals(githubCloud.getRepository().getBranch().getName(), TEST_REPOSITORY_BRANCH_NAME);
        assertEquals(githubCloud.getHost().getUrl(), "");

        Github githubEnterprise = githubRepositoryService.createGithubObject(scanParametersMap, TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER, TEST_REPOSITORY_PULL_NUMBER, TEST_REPOSITORY_BRANCH_NAME,
                TEST_REPOSITORY_URL_ENTERPRISE, true);


        assertEquals(githubEnterprise.getUser().getToken(), scanParametersMap.get(ApplicationConstants.GITHUB_TOKEN_KEY).toString());
        assertEquals(githubEnterprise.getRepository().getName(), TEST_REPOSITORY_NAME);
        assertEquals(githubEnterprise.getRepository().getOwner().getName(), TEST_REPOSITORY_OWNER);
        assertEquals(githubEnterprise.getRepository().getPull().getNumber(), TEST_REPOSITORY_PULL_NUMBER);
        assertEquals(githubEnterprise.getRepository().getBranch().getName(), TEST_REPOSITORY_BRANCH_NAME);
        assertEquals(githubEnterprise.getHost().getUrl(), "https://custom.githubserver.com/");

        Github githubEnterpriseIp = githubRepositoryService.createGithubObject(scanParametersMap, TEST_REPOSITORY_NAME,
                TEST_REPOSITORY_OWNER, TEST_REPOSITORY_PULL_NUMBER, TEST_REPOSITORY_BRANCH_NAME,
                TEST_REPOSITORY_ENTERPRISE_IP, true);

        assertEquals(githubEnterpriseIp.getHost().getUrl(), "https://10.0.0.97:8181/");
    }


    @Test
    void createGithubObjectPluginExceptionTest() throws PluginExceptionHandler {
        scanParametersMap.put(ApplicationConstants.PRODUCT_KEY, "blackduck");

        assertThrows(
                PluginExceptionHandler.class,
                () -> githubRepositoryService.createGithubObject(scanParametersMap, TEST_REPOSITORY_NAME,
                        TEST_REPOSITORY_OWNER, TEST_REPOSITORY_PULL_NUMBER, TEST_REPOSITORY_BRANCH_NAME,
                        TEST_REPOSITORY_URL_CLOUD, true));
    }

    @Test
    void extractGitHubHostTest() {
        String githubCloudHost = githubRepositoryService.extractGitHubHost(TEST_REPOSITORY_URL_CLOUD);
        String githubEnterPriseHost = githubRepositoryService.extractGitHubHost(TEST_REPOSITORY_URL_ENTERPRISE);
        String githubEnterpriseIpHost = githubRepositoryService.extractGitHubHost(TEST_REPOSITORY_ENTERPRISE_IP);
        String invalidGithubHost = githubRepositoryService.extractGitHubHost("invalid.url");

        assertEquals(githubCloudHost, "https://github.com/");
        assertEquals(githubEnterPriseHost, "https://custom.githubserver.com/");
        assertEquals(githubEnterpriseIpHost, "https://10.0.0.97:8181/");
        assertEquals(invalidGithubHost, "Invalid Github repository URL");
    }
}