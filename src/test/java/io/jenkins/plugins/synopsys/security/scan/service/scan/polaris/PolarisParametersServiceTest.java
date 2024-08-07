package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck.BlackDuckParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.coverity.CoverityParametersService;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PolarisParametersServiceTest {
    private PolarisParametersService polarisParametersService;
    private BlackDuckParametersService blackDuckParametersService;
    private CoverityParametersService coverityParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_POLARIS_SERVER_URL = "https://fake.polaris-server.url";
    private final String TEST_POLARIS_ACCESS_TOKEN = "fakePolarisAccessToken";
    private final String TEST_APPLICATION_NAME = "fake-polaris-application-name";
    private final String TEST_PROJECT_NAME = "fake-polaris-project-name";
    private final String TEST_POLARIS_ASSESSMENT_TYPES = "SCA, SAST";
    private final String TEST_POLARIS_BRANCH_NAME = "test-branch";
    private final Boolean TEST_POLARIS_PRCOMMENT_ENABLED = true;
    private final String TEST_POLARIS_BRANCH_PARENT_NAME = "test-parent-branch";
    private final String TEST_POLARIS_PRCOMMENT_SEVERITIES = "HIGH, CRITICAL";
    private final String TEST_POLARIS_ASSESSMENT_MODE = "SOURCE_UPLOAD";
    private final String TEST_PROJECT_DIRECTORY = "DIR/TEST";
    private final String TEST_PROJECT_SOURCE_ARCHIVE = "TEST.ZIP";
    private final String TEST_PROJECT_SOURCE_EXCLUDES = "TEST1, TEST2";
    private final Boolean TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS = true;
    private final String TEST_BLACKDUCK_ARGS = "--detect.diagnostic=true";
    private final String TEST_BLACKDUCK_CONFIG_FILE_PATH = "DIR/CONFIG/application.properties";
    private final String TEST_COVERITY_CLEAN_COMMAND = "mvn clean";
    private final String TEST_COVERITY_BUILD_COMMAND = "mvn clean install";
    private final String TEST_COVERITY_ARGS = "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install";
    private final String TEST_COVERITY_CONFIG_FILE_PATH = "DIR/CONFIG/coverity.yml";

    @BeforeEach
    void setUp() {
        polarisParametersService = new PolarisParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        assertFalse(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);

        assertFalse(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, TEST_PROJECT_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, TEST_POLARIS_ASSESSMENT_TYPES);
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, TEST_POLARIS_BRANCH_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, TEST_POLARIS_BRANCH_PARENT_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, TEST_POLARIS_PRCOMMENT_ENABLED);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, TEST_POLARIS_PRCOMMENT_SEVERITIES);
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY, TEST_POLARIS_ASSESSMENT_MODE);
        polarisParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY, TEST_PROJECT_SOURCE_ARCHIVE);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY, TEST_PROJECT_SOURCE_EXCLUDES);
        polarisParameters.put(
                ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY, TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS);

        assertTrue(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));
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
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, "SCA-PACKAGE");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
        assertEquals(polaris.getTriage(), "REQUIRED");
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertEquals(polaris.getTest().getSca().getType(), "SCA-PACKAGE");
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
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, "SCA-SIGNATURE");

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
        assertEquals(polaris.getTest().getSca().getType(), "SCA-SIGNATURE");
    }

    @Test
    void prepareScanInputForBridgeForPolarisAndSourceUploadTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY, TEST_POLARIS_ASSESSMENT_MODE);
        polarisParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY, TEST_PROJECT_SOURCE_ARCHIVE);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY, "TEST");
        polarisParameters.put(
                ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY, TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS);

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);
        Project project = polarisParametersService.prepareProjectObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
        assertEquals(polaris.getAssessmentTypes().getMode(), TEST_POLARIS_ASSESSMENT_MODE);
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
        assertEquals(project.getSource().getArchive(), TEST_PROJECT_SOURCE_ARCHIVE);
        assertEquals(project.getSource().getExcludes(), Arrays.asList("TEST"));
        assertTrue(project.getSource().getPreserveSymLinks());
    }

    @Test
    void prepareScanInputForBridgeForPolaris_SCA_SAST_ArbitraryParamsTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.BLACKDUCK_SEARCH_DEPTH_KEY, 2);
        polarisParameters.put(ApplicationConstants.BLACKDUCK_CONFIG_PATH_KEY, TEST_BLACKDUCK_CONFIG_FILE_PATH);
        polarisParameters.put(ApplicationConstants.BLACKDUCK_ARGS_KEY, TEST_BLACKDUCK_ARGS);
        polarisParameters.put(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY, TEST_COVERITY_BUILD_COMMAND);
        polarisParameters.put(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY, TEST_COVERITY_CLEAN_COMMAND);
        polarisParameters.put(ApplicationConstants.COVERITY_CONFIG_PATH_KEY, TEST_COVERITY_CONFIG_FILE_PATH);
        polarisParameters.put(ApplicationConstants.COVERITY_ARGS_KEY, TEST_COVERITY_ARGS);

        blackDuckParametersService = new BlackDuckParametersService(listenerMock, envVarsMock);
        coverityParametersService = new CoverityParametersService(listenerMock, envVarsMock);

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);
        BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(polarisParameters);
        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
        assertEquals(2, blackDuck.getSearch().getDepth());
        assertEquals(TEST_BLACKDUCK_CONFIG_FILE_PATH, blackDuck.getConfig().getPath());
        assertEquals(TEST_BLACKDUCK_ARGS, blackDuck.getArgs());
        assertEquals(coverity.getBuild().getCommand(), TEST_COVERITY_BUILD_COMMAND);
        assertEquals(coverity.getClean().getCommand(), TEST_COVERITY_CLEAN_COMMAND);
        assertEquals(coverity.getConfig().getPath(), TEST_COVERITY_CONFIG_FILE_PATH);
        assertEquals(coverity.getArgs(), TEST_COVERITY_ARGS);
    }
}
