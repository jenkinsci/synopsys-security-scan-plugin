package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PolarisParametersServiceTest {
    private PolarisParametersService polarisParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_POLARIS_SERVER_URL = "https://fake.polaris-server.url";
    private final String TEST_POLARIS_ACCESS_TOKEN = "fakePolarisAccessToken";
    private final String TEST_APPLICATION_NAME = "fake-polaris-application-name";
    private final String TEST_POLARIS_ASSESSMENT_TYPES = "SCA, SAST";
    private final String TEST_POLARIS_BRANCH_NAME = "test-branch";
    private final Boolean TEST_POLARIS_PRCOMMENT_ENABLED = true;
    private final String TEST_POLARIS_BRANCH_PARENT_NAME = "test-parent-branch";
    private final String TEST_POLARIS_PRCOMMENT_SEVERITIES = "HIGH, CRITICAL";

    @BeforeEach
    void setUp() {
        polarisParametersService = new PolarisParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        assertFalse(polarisParametersService.isValidPolarisParameters(polarisParameters));

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);

        assertFalse(polarisParametersService.isValidPolarisParameters(polarisParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, TEST_POLARIS_ASSESSMENT_TYPES);
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, TEST_POLARIS_BRANCH_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, TEST_POLARIS_BRANCH_PARENT_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, TEST_POLARIS_PRCOMMENT_ENABLED);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, TEST_POLARIS_PRCOMMENT_SEVERITIES);

        assertTrue(polarisParametersService.isValidPolarisParameters(polarisParameters));
    }

    @Test
    void prepareScanInputForBridgeForNonPPContextTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_TRIAGE_KEY, "REQUIRED");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "HIGH");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
        assertEquals(polaris.getTriage(), "REQUIRED");
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertNull(polaris.getBranch().getParent());
        assertNull(polaris.getPrcomment());
    }

    @Test
    void prepareScanInputForBridgeForPPContextTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_TRIAGE_KEY, "REQUIRED");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "HIGH");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
        assertEquals(polaris.getTriage(), "REQUIRED");
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertEquals(polaris.getBranch().getParent().getName(), "test-parent-branch");
        assertEquals(polaris.getPrcomment().getEnabled(), true);
        assertEquals(polaris.getPrcomment().getSeverities(), Arrays.asList("HIGH"));
    }
}
