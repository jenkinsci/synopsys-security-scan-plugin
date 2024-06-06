package io.jenkins.plugins.synopsys.security.scan.service.scan.coverity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CoverityParametersServiceTest {
    private CoverityParametersService coverityParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_COVERITY_URL = "https://fake.coverity.url";
    private final String TEST_COVERITY_USER_NAME = "fake-user";
    private final String TEST_COVERITY_USER_PASSWORD = "fakeUserPassword";

    @BeforeEach
    void setUp() {
        coverityParametersService = new CoverityParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        assertFalse(coverityParametersService.isValidCoverityParameters(coverityParameters));

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);

        assertFalse(coverityParametersService.isValidCoverityParameters(coverityParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");

        assertTrue(coverityParametersService.isValidCoverityParameters(coverityParameters));
    }

    @Test
    void prepareScanInputForBridgeNonPRContextTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, "2023.6.0");
        coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, true);
        coverityParameters.put(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY, true);

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(coverity.getVersion(), "2023.6.0");
        assertTrue(coverity.isLocal());
        assertNull(coverity.getAutomation());
    }

    @Test
    void prepareScanInputForBridgePRContextTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, "2023.6.0");
        coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, true);
        coverityParameters.put(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY, true);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(coverity.getVersion(), "2023.6.0");
        assertTrue(coverity.isLocal());
        assertTrue(coverity.getAutomation().getPrComment());
    }

    @Test
    void prepareScanInputForBridgeForCoverityAndProjectDirectoryTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, "DIR/TEST");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);
        Project project = coverityParametersService.prepareProjectObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(project.getDirectory(), "DIR/TEST");
    }
}
