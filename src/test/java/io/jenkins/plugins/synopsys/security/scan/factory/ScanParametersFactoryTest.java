package io.jenkins.plugins.synopsys.security.scan.factory;

import static org.junit.jupiter.api.Assertions.*;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.extension.pipeline.SecurityScanStep;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import java.io.File;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class ScanParametersFactoryTest {
    private TaskListener listenerMock;
    private FilePath workspace;
    private EnvVars envVarsMock;
    private SecurityScanStep securityScanStep;

    @BeforeEach
    public void setUp() {
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        envVarsMock = Mockito.mock(EnvVars.class);
        securityScanStep = new SecurityScanStep();
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    public void preparePipelineParametersMapTest() throws AbortException, PluginExceptionHandler {
        Map<String, Object> globalConfigValues = new HashMap<>();

        securityScanStep.setProduct("BLACKDUCK");
        securityScanStep.setBitbucket_token("FAKETOKEN");
        globalConfigValues.put(ApplicationConstants.BLACKDUCK_URL_KEY, "https://fake-blackduck.url");
        globalConfigValues.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, "fake-blackduck-token");
        globalConfigValues.put(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY, "/fake/path");

        Map<String, Object> result =
                ScanParametersFactory.preparePipelineParametersMap(securityScanStep, globalConfigValues, listenerMock);

        assertEquals(5, result.size());
        assertEquals("BLACKDUCK", result.get(ApplicationConstants.PRODUCT_KEY));
        assertEquals("fake-blackduck-token", result.get(ApplicationConstants.BLACKDUCK_TOKEN_KEY));
        assertEquals("/fake/path", result.get(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY));
        assertEquals("FAKETOKEN", result.get(ApplicationConstants.BITBUCKET_TOKEN_KEY));

        securityScanStep.setProduct("invalid-product");

        assertThrows(
                PluginExceptionHandler.class,
                () -> ScanParametersFactory.preparePipelineParametersMap(
                        securityScanStep, globalConfigValues, listenerMock));
    }

    @Test
    public void prepareBlackDuckParametersMapTest() {
        securityScanStep.setBlackduck_url("https://fake.blackduck-url");
        securityScanStep.setBlackduck_token("fake-token");
        securityScanStep.setBlackduck_install_directory("/fake/path");
        securityScanStep.setBlackduck_scan_full(true);
        securityScanStep.setBlackduck_automation_prcomment(true);
        securityScanStep.setBlackduck_download_url("https://fake.blackduck-download-url");
        securityScanStep.setBlackduck_scan_failure_severities("MAJOR");

        Map<String, Object> blackDuckParametersMap =
                ScanParametersFactory.prepareBlackDuckParametersMap(securityScanStep);

        assertEquals(7, blackDuckParametersMap.size());
        assertEquals("https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_DOWNLOAD_URL_KEY));
        assertEquals("MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY));

        Map<String, Object> emptyBlackDuckParametersMap =
                ScanParametersFactory.prepareBlackDuckParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBlackDuckParametersMap.size());
    }

    @Test
    public void prepareCoverityParametersMapTest() {
        securityScanStep.setCoverity_url("https://fake.coverity-url");
        securityScanStep.setCoverity_user("fake-user");
        securityScanStep.setCoverity_passphrase("fake-passphrase");
        securityScanStep.setCoverity_project_name("fake-project");
        securityScanStep.setCoverity_stream_name("fake-stream");
        securityScanStep.setCoverity_policy_view("fake-policy");
        securityScanStep.setCoverity_install_directory("/fake/path");
        securityScanStep.setCoverity_automation_prcomment(true);
        securityScanStep.setCoverity_version("1.0.0");
        securityScanStep.setCoverity_local(true);

        Map<String, Object> coverityParametersMap =
                ScanParametersFactory.prepareCoverityParametersMap(securityScanStep);

        assertEquals(10, coverityParametersMap.size());
        assertEquals("https://fake.coverity-url", coverityParametersMap.get(ApplicationConstants.COVERITY_URL_KEY));
        assertEquals("fake-user", coverityParametersMap.get(ApplicationConstants.COVERITY_USER_KEY));
        assertEquals("fake-passphrase", coverityParametersMap.get(ApplicationConstants.COVERITY_PASSPHRASE_KEY));
        assertEquals("fake-project", coverityParametersMap.get(ApplicationConstants.COVERITY_PROJECT_NAME_KEY));
        assertEquals("fake-stream", coverityParametersMap.get(ApplicationConstants.COVERITY_STREAM_NAME_KEY));
        assertEquals("fake-policy", coverityParametersMap.get(ApplicationConstants.COVERITY_POLICY_VIEW_KEY));
        assertEquals("/fake/path", coverityParametersMap.get(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) coverityParametersMap.get(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY));
        assertEquals("1.0.0", coverityParametersMap.get(ApplicationConstants.COVERITY_VERSION_KEY));
        assertTrue(coverityParametersMap.containsKey(ApplicationConstants.COVERITY_LOCAL_KEY));

        Map<String, Object> emptyCoverityParametersMap =
                ScanParametersFactory.prepareCoverityParametersMap(new SecurityScanStep());
        assertEquals(0, emptyCoverityParametersMap.size());
    }

    @Test
    public void prepareBridgeParametersMapTest() {
        securityScanStep.setSynopsys_bridge_download_url("https://fake.bridge-download.url");
        securityScanStep.setSynopsys_bridge_download_version("1.0.0");
        securityScanStep.setSynopsys_bridge_install_directory("/fake/path");
        securityScanStep.setInclude_diagnostics(true);
        securityScanStep.setNetwork_airgap(true);

        Map<String, Object> bridgeParametersMap = ScanParametersFactory.prepareBridgeParametersMap(securityScanStep);

        assertEquals(5, bridgeParametersMap.size());
        assertEquals(
                "https://fake.bridge-download.url",
                bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL));
        assertEquals("1.0.0", bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION));
        assertEquals("/fake/path", bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.NETWORK_AIRGAP_KEY));

        Map<String, Object> emptyBridgeParametersMap =
                ScanParametersFactory.prepareBridgeParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBridgeParametersMap.size());
    }

    @Test
    public void preparePolarisParametersMapTest() {
        securityScanStep.setPolaris_server_url("https://fake.polaris-server.url");
        securityScanStep.setPolaris_access_token("fake-access-token");
        securityScanStep.setPolaris_application_name("fake-application-name");
        securityScanStep.setPolaris_project_name("fake-project-name");
        securityScanStep.setPolaris_assessment_types("SCA");
        securityScanStep.setPolaris_triage("REQUIRED");
        securityScanStep.setPolaris_branch_name("test");

        Map<String, Object> polarisParametersMap = ScanParametersFactory.preparePolarisParametersMap(securityScanStep);

        assertEquals(7, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("REQUIRED", polarisParametersMap.get(ApplicationConstants.POLARIS_TRIAGE_KEY));
    }

    @Test
    public void getSynopsysBridgeDownloadUrlBasedOnAgentOSTest() {
        String downloadUrlLinux = "https://fake-url.com/linux";
        String downloadUrlMac = "https://fake-url.com/mac";
        String downloadUrlWindows = "https://fake-url.com/windows";

        String os = System.getProperty("os.name").toLowerCase();
        String agentSpecificDownloadUrl = ScanParametersFactory.getSynopsysBridgeDownloadUrlBasedOnAgentOS(
                workspace, listenerMock, downloadUrlMac, downloadUrlLinux, downloadUrlWindows);

        if (os.contains("linux")) {
            assertEquals(downloadUrlLinux, agentSpecificDownloadUrl);
        } else if (os.contains("mac")) {
            assertEquals(downloadUrlMac, agentSpecificDownloadUrl);
        } else {
            assertEquals(downloadUrlWindows, agentSpecificDownloadUrl);
        }
    }

    @Test
    public void validateProductTest() {
        assertTrue(ScanParametersFactory.validateProduct("blackduck", listenerMock));
        assertTrue(ScanParametersFactory.validateProduct("POLARIS", listenerMock));
        assertTrue(ScanParametersFactory.validateProduct("COveRiTy", listenerMock));
        assertFalse(ScanParametersFactory.validateProduct("polar1s", listenerMock));
    }
}
