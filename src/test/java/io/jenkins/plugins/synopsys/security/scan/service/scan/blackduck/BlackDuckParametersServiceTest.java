package io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BlackDuckParametersServiceTest {
    private BlackDuckParametersService blackDuckParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_BLACKDUCK_URL = "https://fake.blackduck.url";
    private final String TEST_BLACKDUCK_TOKEN = "MDJDSROSVC56FAKEKEY";
    private final String TEST_BLACKDUCK_INSTALL_DIRECTORY_PATH = "/path/to/blackduck/directory";
    private final String TEST_PROJECT_DIRECTORY = "DIR/TEST";
    private final String TEST_BLACKDUCK_ARGS = "--detect.diagnostic=true";
    private final String TEST_BLACKDUCK_CONFIG_FILE_PATH = "DIR/CONFIG/application.properties";
    private final Boolean TEST_SRM_WAIT_FOR_SCAN = true;

    @BeforeEach
    void setUp() {
        blackDuckParametersService = new BlackDuckParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void createBlackDuckObjectForNonPRContextTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY, TEST_BLACKDUCK_INSTALL_DIRECTORY_PATH);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        blackDuckParametersMap.put(ApplicationConstants.WAIT_FOR_SCAN_KEY, TEST_SRM_WAIT_FOR_SCAN);

        BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCK_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCK_TOKEN, blackDuck.getToken());
        assertEquals(
                TEST_BLACKDUCK_INSTALL_DIRECTORY_PATH, blackDuck.getInstall().getDirectory());
        assertEquals(null, blackDuck.getAutomation());
        assertEquals(true, blackDuck.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuck.getScan().getFailure().getSeverities());
        assertEquals(blackDuck.isWaitForScan(), TEST_SRM_WAIT_FOR_SCAN);
    }

    @Test
    void createBlackDuckObjectForPRContextTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY, TEST_BLACKDUCK_INSTALL_DIRECTORY_PATH);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckParametersMap.put(ApplicationConstants.WAIT_FOR_SCAN_KEY, TEST_SRM_WAIT_FOR_SCAN);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCK_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCK_TOKEN, blackDuck.getToken());
        assertEquals(
                TEST_BLACKDUCK_INSTALL_DIRECTORY_PATH, blackDuck.getInstall().getDirectory());
        assertEquals(true, blackDuck.getAutomation().getPrComment());
        assertEquals(true, blackDuck.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuck.getScan().getFailure().getSeverities());
        assertEquals(blackDuck.isWaitForScan(), TEST_SRM_WAIT_FOR_SCAN);
    }

    @Test
    void validateBlackDuckParametersForValidParametersTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);

        assertTrue(blackDuckParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void validateBlackDuckParametersForMissingParametersTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);

        assertFalse(blackDuckParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void validateBlackDuckParametersForNullAndEmptyTest() {
        assertFalse(blackDuckParametersService.isValidBlackDuckParameters(null));

        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, "");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);

        assertFalse(blackDuckParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void prepareScanInputForBridgeForBlackduckAndProjectDirectoryTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);

        BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);
        Project project = blackDuckParametersService.prepareProjectObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCK_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCK_TOKEN, blackDuck.getToken());
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
    }

    @Test
    void prepareScanBridgeInputForBlackduckArbitraryParamsTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, TEST_BLACKDUCK_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TEST_BLACKDUCK_TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_SEARCH_DEPTH_KEY, 2);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_CONFIG_PATH_KEY, TEST_BLACKDUCK_CONFIG_FILE_PATH);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_ARGS_KEY, TEST_BLACKDUCK_ARGS);

        BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCK_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCK_TOKEN, blackDuck.getToken());
        assertEquals(2, blackDuck.getSearch().getDepth());
        assertEquals(TEST_BLACKDUCK_CONFIG_FILE_PATH, blackDuck.getConfig().getPath());
        assertEquals(TEST_BLACKDUCK_ARGS, blackDuck.getArgs());
    }
}
