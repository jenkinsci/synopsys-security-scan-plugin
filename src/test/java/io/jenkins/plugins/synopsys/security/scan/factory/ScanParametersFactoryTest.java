package io.jenkins.plugins.synopsys.security.scan.factory;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.extension.freestyle.SecurityScanFreestyle;
import io.jenkins.plugins.synopsys.security.scan.extension.pipeline.SecurityScanStep;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
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
    private SecurityScanFreestyle securityScanFreestyle;

    @BeforeEach
    public void setUp() {
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        envVarsMock = Mockito.mock(EnvVars.class);
        securityScanStep = new SecurityScanStep();
        securityScanFreestyle = new SecurityScanFreestyle();
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    public void preparePipelineParametersMapTest() throws PluginExceptionHandler {
        Map<String, Object> globalConfigValues = new HashMap<>();

        securityScanStep.setProduct("BLACKDUCK");
        securityScanStep.setBitbucket_token("FAKETOKEN");
        securityScanStep.setGithub_token("faketoken-github");
        securityScanStep.setGitlab_token("fakeTokeN-gItlAb");
        globalConfigValues.put(ApplicationConstants.BLACKDUCK_URL_KEY, "https://fake-blackduck.url");
        globalConfigValues.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, "fake-blackduck-token");
        globalConfigValues.put(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY, "/fake/path");

        Map<String, Object> result =
                ScanParametersFactory.preparePipelineParametersMap(securityScanStep, globalConfigValues, listenerMock);

        assertEquals(8, result.size());
        assertEquals("BLACKDUCK", result.get(ApplicationConstants.PRODUCT_KEY));
        assertEquals("fake-blackduck-token", result.get(ApplicationConstants.BLACKDUCK_TOKEN_KEY));
        assertEquals("/fake/path", result.get(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY));
        assertEquals("FAKETOKEN", result.get(ApplicationConstants.BITBUCKET_TOKEN_KEY));
        assertEquals("faketoken-github", result.get(ApplicationConstants.GITHUB_TOKEN_KEY));
        assertEquals("fakeTokeN-gItlAb", result.get(ApplicationConstants.GITLAB_TOKEN_KEY));

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
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setBlackduck_search_depth(2);
        securityScanStep.setBlackduck_config_path("fake/directory/application.properties");
        securityScanStep.setBlackduck_args("--o");

        Map<String, Object> blackDuckParametersMap =
                ScanParametersFactory.prepareBlackDuckParametersMap(securityScanStep);

        assertEquals(11, blackDuckParametersMap.size());
        assertEquals("https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_DOWNLOAD_URL_KEY));
        assertEquals("MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY));
        assertEquals("test/directory", blackDuckParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals(2, blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/directory/application.properties",
                blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_CONFIG_PATH_KEY));
        assertEquals("--o", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCK_ARGS_KEY));
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
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setCoverity_build_command("fake-build-command");
        securityScanStep.setCoverity_clean_command("fake-clean-command");
        securityScanStep.setCoverity_config_path("fake-config-path");
        securityScanStep.setCoverity_args("--o");

        Map<String, Object> coverityParametersMap =
                ScanParametersFactory.prepareCoverityParametersMap(securityScanStep);

        assertEquals(15, coverityParametersMap.size());
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
        assertEquals("test/directory", coverityParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-build-command", coverityParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("fake-clean-command", coverityParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake-config-path", coverityParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", coverityParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));

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

        Map<String, Object> bridgeParametersMap = ScanParametersFactory.prepareAddtionalParametersMap(securityScanStep);

        assertEquals(5, bridgeParametersMap.size());
        assertEquals(
                "https://fake.bridge-download.url",
                bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL));
        assertEquals("1.0.0", bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION));
        assertEquals("/fake/path", bridgeParametersMap.get(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.NETWORK_AIRGAP_KEY));

        Map<String, Object> emptyBridgeParametersMap =
                ScanParametersFactory.prepareAddtionalParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBridgeParametersMap.size());
    }

    @Test
    public void preparePolarisParametersMapForMultibranchTest() {
        securityScanStep.setPolaris_server_url("https://fake.polaris-server.url");
        securityScanStep.setPolaris_access_token("fake-access-token");
        securityScanStep.setPolaris_application_name("fake-application-name");
        securityScanStep.setPolaris_project_name("fake-project-name");
        securityScanStep.setPolaris_assessment_types("SCA");
        securityScanStep.setPolaris_triage("REQUIRED");
        securityScanStep.setPolaris_branch_name("test");
        securityScanStep.setPolaris_branch_parent_name("master");
        securityScanStep.setPolaris_prComment_enabled(true);
        securityScanStep.setPolaris_prComment_severities("high, critical");
        securityScanStep.setPolaris_assessment_mode("SOURCE_UPLOAD");
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setProject_source_archive("fake-source-archive");
        securityScanStep.setProject_source_preserveSymLinks(true);
        securityScanStep.setProject_source_excludes("test_exclude");

        Map<String, Object> polarisParametersMap = ScanParametersFactory.preparePolarisParametersMap(securityScanStep);

        assertEquals(15, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("REQUIRED", polarisParametersMap.get(ApplicationConstants.POLARIS_TRIAGE_KEY));
        assertEquals("master", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY));
        assertEquals(true, polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY));
        assertEquals("high, critical", polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY));
        assertEquals("SOURCE_UPLOAD", polarisParametersMap.get(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY));
        assertEquals("test/directory", polarisParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-source-archive", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY));
        assertEquals("test_exclude", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY));
        assertTrue((Boolean) polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY));
    }

    @Test
    public void preparePolarisParametersMapForFreestyleTest() {
        securityScanFreestyle.setProduct("POLARIS");
        securityScanFreestyle.setBitbucket_token("FAKETOKEN");
        securityScanFreestyle.setGithub_token("faketoken-github");
        securityScanFreestyle.setGitlab_token("fakeTokeN-gItlAb");
        securityScanFreestyle.setPolaris_server_url("https://fake.polaris-server.url");
        securityScanFreestyle.setPolaris_access_token("fake-access-token");
        securityScanFreestyle.setPolaris_application_name("fake-application-name");
        securityScanFreestyle.setPolaris_project_name("fake-project-name");
        securityScanFreestyle.setPolaris_assessment_types("SCA");
        securityScanFreestyle.setPolaris_branch_name("test");
        securityScanFreestyle.setPolaris_sast_build_command("mvn clean install");
        securityScanFreestyle.setPolaris_sast_clean_command("mvn clean install");
        securityScanFreestyle.setPolaris_sast_config_path("fake/path/config.yml");
        securityScanFreestyle.setPolaris_sast_args("--o");
        securityScanFreestyle.setPolaris_sca_search_depth(2);
        securityScanFreestyle.setPolaris_sca_config_path("fake/path/application.properties");
        securityScanFreestyle.setPolaris_sca_args("--o");

        Map<String, Object> polarisParametersMap =
                ScanParametersFactory.preparePolarisParametersMap(securityScanFreestyle);

        assertEquals(13, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("mvn clean install", polarisParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("mvn clean install", polarisParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake/path/config.yml", polarisParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", polarisParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));
        assertEquals(2, polarisParametersMap.get(ApplicationConstants.BLACKDUCK_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/path/application.properties",
                polarisParametersMap.get(ApplicationConstants.BLACKDUCK_CONFIG_PATH_KEY));
        assertEquals("--o", polarisParametersMap.get(ApplicationConstants.BLACKDUCK_ARGS_KEY));
    }

    @Test
    public void prepareSarifReportParametersMap() {
        securityScanStep.setBlackduck_reports_sarif_create(true);
        securityScanStep.setBlackduck_reports_sarif_file_path("/fake/path");
        securityScanStep.setBlackduck_reports_sarif_severities("CRITICAL");
        securityScanStep.setBlackduck_reports_sarif_groupSCAIssues(true);

        Map<String, Object> sarifParametersMap =
                ScanParametersFactory.prepareSarifReportParametersMap(securityScanStep);

        assertEquals(4, sarifParametersMap.size());
        assertTrue((boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY));
        assertEquals("/fake/path", sarifParametersMap.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY));
        assertEquals("CRITICAL", sarifParametersMap.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY));
        assertTrue((boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY));

        Map<String, Object> emptySarifParametersMap =
                ScanParametersFactory.prepareSarifReportParametersMap(new SecurityScanStep());

        assertEquals(0, emptySarifParametersMap.size());
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

    @Test
    public void getBuildResultIfIssuesAreFoundTest() {
        LoggerWrapper loggerMock = new LoggerWrapper(listenerMock);

        assertEquals(
                ScanParametersFactory.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "FAILURE", loggerMock),
                Result.FAILURE);
        assertEquals(
                ScanParametersFactory.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "UNSTABLE", loggerMock),
                Result.UNSTABLE);
        assertEquals(
                ScanParametersFactory.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "SUCCESS", loggerMock),
                Result.SUCCESS);
        assertNull(ScanParametersFactory.getBuildResultIfIssuesAreFound(
                ErrorCode.BRIDGE_BUILD_BREAK, "ABORTED", loggerMock));
        assertNull(ScanParametersFactory.getBuildResultIfIssuesAreFound(
                ErrorCode.BRIDGE_ADAPTER_ERROR, "UNSTABLE", loggerMock));
    }
}
