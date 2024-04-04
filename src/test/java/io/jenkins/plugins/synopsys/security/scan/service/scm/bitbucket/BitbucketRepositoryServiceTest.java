package io.jenkins.plugins.synopsys.security.scan.service.scm.bitbucket;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketApi;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketRepository;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket.Bitbucket;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BitbucketRepositoryServiceTest {
    private final BitbucketRepositoryService bitbucketRepositoryServiceMock =
            Mockito.mock(BitbucketRepositoryService.class);
    private final String TEST_BITBUCKET_URL = "https://fake.bitbucket.url";
    private final String TEST_BITBUCKET_TOKEN = "MSDFSGOIIEGWGWEGFAKEKEY";
    private final Integer TEST_REPOSITORY_PULL_NUMBER = 7;
    private final String TEST_REPOSITORY_NAME = "TEST_REPO";
    private final String TEST_PROJECT_KEY = "my_key";
    private final String TEST_REPOSITORY_BRANCH_NAME = "TEST_BRANCH";
    private final String TEST_REPOSITORY_PARENT_BRANCH_NAME = "TEST_PARENT_BRANCH";
    Map<String, Object> bitbucketParametersMap = new HashMap<>();
    private BitbucketSCMSource bitbucketSCMSourceMock;
    private TaskListener listenerMock;

    @BeforeEach
    void setUp() throws PluginExceptionHandler {
        Bitbucket bitbucket = BitbucketRepositoryService.createBitbucketObject(
                TEST_BITBUCKET_URL,
                TEST_BITBUCKET_TOKEN,
                TEST_REPOSITORY_PULL_NUMBER,
                TEST_REPOSITORY_NAME,
                TEST_PROJECT_KEY,
                null,
                null);

        bitbucketParametersMap.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, TEST_BITBUCKET_TOKEN);

        bitbucketSCMSourceMock = mock(BitbucketSCMSource.class);

        when(bitbucketRepositoryServiceMock.fetchBitbucketRepositoryDetails(
                        bitbucketParametersMap, bitbucketSCMSourceMock, TEST_REPOSITORY_PULL_NUMBER, false, TEST_REPOSITORY_BRANCH_NAME, TEST_REPOSITORY_PARENT_BRANCH_NAME))
                .thenReturn(bitbucket);

        listenerMock = Mockito.mock(TaskListener.class);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void createBitbucketObjectTest() throws PluginExceptionHandler {
        Bitbucket bitbucket = bitbucketRepositoryServiceMock.fetchBitbucketRepositoryDetails(
                bitbucketParametersMap, bitbucketSCMSourceMock, TEST_REPOSITORY_PULL_NUMBER, false, TEST_REPOSITORY_BRANCH_NAME, TEST_REPOSITORY_PARENT_BRANCH_NAME);

        assertEquals(TEST_BITBUCKET_URL, bitbucket.getApi().getUrl());
        assertEquals(TEST_BITBUCKET_TOKEN, bitbucket.getApi().getToken());
        assertEquals(
                TEST_REPOSITORY_PULL_NUMBER,
                bitbucket.getProject().getRepository().getPull().getNumber());
        assertEquals(
                TEST_REPOSITORY_NAME, bitbucket.getProject().getRepository().getName());
        assertEquals(TEST_PROJECT_KEY, bitbucket.getProject().getKey());
    }

    @Test
    public void fetchBitbucketRepositoryDetailsTest() throws PluginExceptionHandler, IOException, InterruptedException {
        Map<String, Object> scanParameters = new HashMap<>();
        BitbucketSCMSource bitbucketSCMSource = mock(BitbucketSCMSource.class);
        BitbucketApi bitbucketApiFromSCMSource = mock(BitbucketApi.class);
        BitbucketRepository bitbucketRepository = mock(BitbucketRepository.class);

        scanParameters.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, "fakeToken");
        when(bitbucketSCMSource.buildBitbucketClient(anyString(), anyString())).thenReturn(bitbucketApiFromSCMSource);
        when(bitbucketApiFromSCMSource.getRepository()).thenReturn(bitbucketRepository);

        BitbucketRepositoryService bitbucketRepositoryService = new BitbucketRepositoryService(listenerMock);
        Bitbucket result =
                bitbucketRepositoryService.fetchBitbucketRepositoryDetails(scanParameters, bitbucketSCMSource, 1, true, TEST_REPOSITORY_BRANCH_NAME, TEST_REPOSITORY_PARENT_BRANCH_NAME);

        assertNotNull(result);

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, "");
        assertThrows(
                PluginExceptionHandler.class,
                () -> bitbucketRepositoryService.fetchBitbucketRepositoryDetails(
                        scanParameters, bitbucketSCMSource, 1, true, TEST_REPOSITORY_BRANCH_NAME, TEST_REPOSITORY_PARENT_BRANCH_NAME));
    }
}
