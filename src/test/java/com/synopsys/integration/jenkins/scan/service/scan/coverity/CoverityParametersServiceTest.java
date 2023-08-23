package com.synopsys.integration.jenkins.scan.service.scan.coverity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.synopsys.integration.jenkins.scan.global.ApplicationConstants;
import com.synopsys.integration.jenkins.scan.global.enums.ScanType;
import com.synopsys.integration.jenkins.scan.input.coverity.Coverity;
import hudson.model.TaskListener;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CoverityParametersServiceTest {
    private CoverityParametersService coverityParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final String TEST_COVERITY_URL = "https://fake.coverity.url";
    private final String TEST_COVERITY_USER_NAME = "fake-user";
    private final String TEST_COVERITY_USER_PASSWORD = "fakeUserPassword";

    @BeforeEach
    void setUp() {
        coverityParametersService = new CoverityParametersService(listenerMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void getScanTypeTest() {
        assertNotEquals(ScanType.BLACKDUCK, coverityParametersService.getScanType());
        assertNotEquals(ScanType.POLARIS, coverityParametersService.getScanType());
        assertEquals(ScanType.COVERITY, coverityParametersService.getScanType());
    }
    
    @Test
    void invalidScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();
        
        assertFalse(coverityParametersService.isValidScanParameters(coverityParameters));
        
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_USER_NAME_KEY, TEST_COVERITY_USER_NAME);
        
        assertFalse(coverityParametersService.isValidScanParameters(coverityParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_USER_NAME_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_USER_PASSWORD_KEY, TEST_COVERITY_USER_PASSWORD);

        assertTrue(coverityParametersService.isValidScanParameters(coverityParameters));
    }

    @Test
    void prepareScanInputForBridgeTest() {
        Map<String, Object> coverityParameters = new HashMap<>();
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_USER_NAME_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_USER_PASSWORD_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_CONNECT_STREAM_NAME_KEY, "fake-repo-branch");

        Coverity coverity = coverityParametersService.prepareScanInputForBridge(coverityParameters);
        
        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
    }
}
