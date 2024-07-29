package io.jenkins.plugins.synopsys.security.scan.service.scan.srm;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck.BlackDuckParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.coverity.CoverityParametersService;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class SRMParametersServiceTest {

    private SRMParametersService srmParametersService;
    private BlackDuckParametersService blackDuckParametersService;
    private CoverityParametersService coverityParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_SRM_SERVER_URL = "https://fake.srm-server.url";
    private final String TEST_SRM_API_KEY_TOKEN = "fakeSrmAPIKey";
    private final String TEST_SRM_PROJECT_NAME = "fake-srm-project-name";
    private final String TEST_SRM_ASSESSMENT_TYPES = "SCA, SAST";
    private final String TEST_SRM_BRANCH_NAME = "test-branch";
    private final String TEST_SRM_BRANCH_PARENT_NAME = "test-parent-branch";
    private final String TEST_BLACKDUCK_EXECUTION_PATH = "/fake/path/bd";
    private final String TEST_COVERITY_EXECUTION_PATH = "/fake/path/cov";

    @BeforeEach
    void setUp() {
        srmParametersService = new SRMParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        assertFalse(srmParametersService.isValidSRMParameters(srmParameters));

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);

        assertFalse(srmParametersService.isValidSRMParameters(srmParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, TEST_SRM_PROJECT_NAME);
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, TEST_SRM_ASSESSMENT_TYPES);
        srmParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, TEST_SRM_BRANCH_NAME);
        srmParameters.put(ApplicationConstants.SRM_BRANCH_PARENT_KEY, TEST_SRM_BRANCH_PARENT_NAME);

        assertTrue(srmParametersService.isValidSRMParameters(srmParameters));
    }
}
