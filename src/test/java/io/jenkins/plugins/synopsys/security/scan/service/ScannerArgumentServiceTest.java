package io.jenkins.plugins.synopsys.security.scan.service;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.BridgeParams;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.synopsys.security.scan.input.BridgeInput;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Automation;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Connect;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import io.jenkins.plugins.synopsys.security.scan.input.report.Sarif;
import io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Github;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.synopsys.security.scan.input.srm.SRM;
import io.jenkins.plugins.synopsys.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.github.GithubRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.gitlab.GitlabRepositoryService;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class ScannerArgumentServiceTest {
    private Bitbucket bitBucket;
    private ScannerArgumentService scannerArgumentService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String CLOUD_API_URI = "https://api.github.com";
    private FilePath workspace;
    private final String TOKEN = "MDJDSROSVC56FAKEKEY";

    @BeforeEach
    void setUp() {
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        workspace = new FilePath(new File(getHomeDirectoryForTest())).child("mock-workspace");

        bitBucket = new Bitbucket();
        bitBucket.getProject().getRepository().setName("fake-repo");

        Mockito.doReturn("fake-branch").when(envVarsMock).get(ApplicationConstants.ENV_BRANCH_NAME_KEY);
        Mockito.doReturn("fake-job/branch").when(envVarsMock).get(ApplicationConstants.ENV_JOB_NAME_KEY);
        Mockito.doReturn("0").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        Mockito.doReturn("fake-main").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_TARGET_KEY);
        Mockito.doReturn("fake-pr-branch").when(envVarsMock).get(ApplicationConstants.ENV_CHANGE_BRANCH_KEY);

        scannerArgumentService = new ScannerArgumentService(listenerMock, envVarsMock, workspace);
    }

    @Test
    void createBlackDuckInputJsonTest() {
        BlackDuck blackDuck = new BlackDuck();
        blackDuck.setUrl("https://fake.blackduck.url");
        blackDuck.setToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                scanParameters,
                blackDuck,
                bitBucket,
                false,
                null,
                null,
                ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX,
                null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    void bitbucket_blackDuckInputJsonTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        BlackDuck blackDuck = new BlackDuck();
        blackDuck.setUrl("https://fake.blackduck.url");
        blackDuck.setToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "abc", "fake-user");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"}}}";

            String inputJsonPathForNonFixPr = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    blackDuck,
                    bitbucketObject,
                    false,
                    null,
                    null,
                    ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            String jsonStringForPrComment =
                    "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"},\"bitbucket\":{\"api\":{\"url\":\"\",\"user\":{\"name\":\"fake-user\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"pull\":{\"number\":12},\"name\":\"test\"},\"key\":\"abc\"}}}}";
            String inputJsonPathForPrComment = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    blackDuck,
                    bitbucketObject,
                    true,
                    null,
                    null,
                    ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForPrComment);

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            String actualJsonString = new String(Files.readAllBytes(Paths.get(inputJsonPathForPrComment)));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void createPolarisInputJsonTest() {
        Polaris polaris = new Polaris();
        polaris.setServerUrl("https://fake.polaris.url");
        polaris.setAccessToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                scanParameters,
                polaris,
                bitBucket,
                false,
                null,
                null,
                ApplicationConstants.POLARIS_INPUT_JSON_PREFIX,
                null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.POLARIS_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    void bitbucket_polarisInputJsonTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        Polaris polaris = new Polaris();
        polaris.setServerUrl("https://fake.polaris.url");
        polaris.setAccessToken(TOKEN);
        Map<String, Object> scanParameters = new HashMap<>();

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "abc", "fake-username");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"polaris\":{\"accesstoken\":\"MDJDSROSVC56FAKEKEY\",\"application\":{\"name\":\"test\"},\"project\":{\"name\":\"test\"},\"assessment\":{},\"serverUrl\":\"https://fake.polaris.url\",\"branch\":{\"name\":\"fake-pr-branch\"}}}}";

            String inputJsonPathForNonFixPr = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    polaris,
                    bitbucketObject,
                    false,
                    null,
                    null,
                    ApplicationConstants.POLARIS_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            String jsonStringForPrComment =
                    "{\"data\":{\"polaris\":{\"accesstoken\":\"MDJDSROSVC56FAKEKEY\",\"application\":{\"name\":\"test\"},\"project\":{\"name\":\"test\"},\"assessment\":{},\"serverUrl\":\"https://fake.polaris.url\",\"branch\":{\"name\":\"fake-pr-branch\"}},\"bitbucket\":{\"api\":{\"url\":\"\",\"user\":{\"name\":\"fake-username\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"pull\":{\"number\":12},\"name\":\"test\"},\"key\":\"abc\"}}}}";
            String inputJsonPathForPrComment = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    polaris,
                    bitbucketObject,
                    true,
                    null,
                    null,
                    ApplicationConstants.POLARIS_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForPrComment);

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            String actualJsonString = new String(Files.readAllBytes(Paths.get(inputJsonPathForPrComment)));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void createSrmInputJsonTest() {
        SRM srm = new SRM();
        srm.setUrl("https://fake.srm.url");
        srm.setApikey(TOKEN);
        srm.getAssessmentTypes().setTypes(List.of("SCA"));
        Map<String, Object> scanParameters = new HashMap<>();

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                scanParameters, srm, bitBucket, false, null, null, ApplicationConstants.SRM_INPUT_JSON_PREFIX, null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.SRM_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    void bitbucket_SrmInputJsonTest() {
        ObjectMapper objectMapper = new ObjectMapper();

        SRM srm = new SRM();
        srm.setUrl("https://fake.srm.url");
        srm.setApikey(TOKEN);
        srm.getAssessmentTypes().setTypes(List.of("SCA"));
        Map<String, Object> scanParameters = new HashMap<>();

        Bitbucket bitbucketObject = BitbucketRepositoryService.createBitbucketObject(
                "https://bitbucket.org", TOKEN, 12, "test", "abc", "fake-user");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"srm\":{\"url\":\"https://fake.srm.url\",\"apikey\":\"MDJDSROSVC56FAKEKEY\",\"assessment\":{\"types\":[\"SCA\"]},\"project\":{\"name\":\"test\"},\"branch\":{}}}}";

            String inputJsonPathForNonFixPr = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    srm,
                    bitbucketObject,
                    false,
                    null,
                    null,
                    ApplicationConstants.SRM_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForNonFixPr);

            String actualJsonString = new String(Files.readAllBytes(filePath));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringNonPrCommentOrFixPr);
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            String jsonStringForPrComment =
                    "{\"data\":{\"srm\":{\"url\":\"https://fake.srm.url\",\"apikey\":\"MDJDSROSVC56FAKEKEY\",\"assessment\":{\"types\":[\"SCA\"]},\"project\":{\"name\":\"test\"},\"branch\":{}},\"bitbucket\":{\"api\":{\"url\":\"\",\"user\":{\"name\":\"fake-user\"},\"token\":\"MDJDSROSVC56FAKEKEY\"},\"project\":{\"repository\":{\"pull\":{\"number\":12},\"name\":\"test\"},\"key\":\"abc\"}}}}";
            String inputJsonPathForPrComment = scannerArgumentService.createBridgeInputJson(
                    scanParameters,
                    srm,
                    bitbucketObject,
                    true,
                    null,
                    null,
                    ApplicationConstants.SRM_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPathForPrComment);

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            String actualJsonString = new String(Files.readAllBytes(Paths.get(inputJsonPathForPrComment)));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void setScmObjectTest() {
        BridgeInput bridgeInput = Mockito.mock(BridgeInput.class);
        Bitbucket bitbucket = Mockito.mock(Bitbucket.class);
        Github github = Mockito.mock(Github.class);
        Gitlab gitlab = Mockito.mock(Gitlab.class);

        scannerArgumentService.setScmObject(bridgeInput, bitbucket);
        Mockito.verify(bridgeInput).setBitbucket(bitbucket);

        scannerArgumentService.setScmObject(bridgeInput, github);
        Mockito.verify(bridgeInput).setGithub(github);

        scannerArgumentService.setScmObject(bridgeInput, gitlab);
        Mockito.verify(bridgeInput).setGitlab(gitlab);
    }

    @Test
    public void setProjectObjectTest() {
        BridgeInput bridgeInput = Mockito.mock(BridgeInput.class);
        Project project = Mockito.mock(Project.class);

        scannerArgumentService.setProjectObject(bridgeInput, project);
        Mockito.verify(bridgeInput).setProject(project);
    }

    @Test
    public void prepareBlackduckSarifObjectTest() {
        Set<String> securityProducts = new HashSet<>();
        securityProducts.add(SecurityProduct.BLACKDUCK.name());
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY, true);
        scanParameters.put(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        scanParameters.put(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        scanParameters.put(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);

        Sarif sarifObject = scannerArgumentService.prepareSarifObject(securityProducts, scanParameters);

        assertNotNull(sarifObject);
        assertTrue(sarifObject.getCreate());
        assertEquals("/path/to/sarif/file", sarifObject.getFile().getPath());
        assertEquals(Arrays.asList("HIGH", "MEDIUM", "LOW"), sarifObject.getSeverities());
        assertTrue(sarifObject.getGroupSCAIssues());
    }

    @Test
    public void preparePolarisSarifObjectTest() {
        Set<String> securityProducts = new HashSet<>();
        securityProducts.add(SecurityProduct.POLARIS.name());
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY, true);
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY, "SCA");

        Sarif sarifObject = scannerArgumentService.prepareSarifObject(securityProducts, scanParameters);

        assertNotNull(sarifObject);
        assertTrue(sarifObject.getCreate());
        assertEquals("/path/to/sarif/file", sarifObject.getFile().getPath());
        assertEquals(Arrays.asList("HIGH", "MEDIUM", "LOW"), sarifObject.getSeverities());
        assertEquals(Arrays.asList("SCA"), sarifObject.getIssue().getTypes());
        assertTrue(sarifObject.getGroupSCAIssues());
    }

    @Test
    public void writeInputJsonToFileTest() {
        String jsonString =
                "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\"}}}";

        String jsonPath = scannerArgumentService.writeInputJsonToFile(
                jsonString, ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX);
        String fileContent = null;
        try {
            fileContent = new String(Files.readAllBytes(Paths.get(jsonPath)));
        } catch (IOException e) {
            e.printStackTrace();
        }

        assertTrue(
                Files.exists(Path.of(jsonPath)),
                String.format(
                        "%s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(jsonString, fileContent);

        Utility.removeFile(jsonPath, workspace, listenerMock);
    }

    @Test
    public void createCoverityInputJsonTest() {
        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");
        Map<String, Object> scanParameters = new HashMap<>();

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                scanParameters,
                coverity,
                bitBucket,
                false,
                null,
                null,
                ApplicationConstants.COVERITY_INPUT_JSON_PREFIX,
                null);
        Path filePath = Paths.get(inputJsonPath);

        assertTrue(
                Files.exists(filePath),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));
        Utility.removeFile(filePath.toString(), workspace, listenerMock);
    }

    @Test
    public void github_coverityInputJsonTest() throws PluginExceptionHandler {
        ObjectMapper objectMapper = new ObjectMapper();
        GithubRepositoryService githubRepositoryService = new GithubRepositoryService(listenerMock);

        Map<String, Object> scanParametersMap = new HashMap<>();
        scanParametersMap.put(ApplicationConstants.GITHUB_TOKEN_KEY, TOKEN);

        String jsonStringForPrComment = "{\"data\":{\"coverity\":{\"connect\":{\"url\":\"https://fake.coverity.url\","
                + "\"user\":{\"name\":\"fake-user\",\"password\":\"fakeUserPassword\"},"
                + "\"project\":{\"name\":\"fake-repo\"},\"stream\":{\"name\":\"fake-repo-fake-main\"}"
                + "}},"
                + "\"github\":{\"user\":{\"token\":\"MDJDSROSVC56FAKEKEY\"},\"repository\":{\"name\":\"fake-repo\""
                + ",\"owner\":{\"name\":\"fake-owner\"},\"pull\":{\"number\":1},\"branch\":{\"name\":"
                + "\"fake-branch\"}}}}}";

        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");

        try {
            Github github = githubRepositoryService.createGithubObject(
                    scanParametersMap, "fake-repo", "fake-owner", 1, "fake-branch", true, CLOUD_API_URI);
            String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                    scanParametersMap,
                    coverity,
                    github,
                    true,
                    null,
                    null,
                    ApplicationConstants.COVERITY_INPUT_JSON_PREFIX,
                    null);
            Path filePath = Paths.get(inputJsonPath);

            assertTrue(
                    Files.exists(filePath),
                    String.format(
                            "File %s does not exist at the specified path.",
                            ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            String actualJsonString = new String(Files.readAllBytes(filePath));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void gitlab_blackDuckInputJsonTest() throws PluginExceptionHandler {
        GitlabRepositoryService gitlabRepositoryService = new GitlabRepositoryService(listenerMock);
        ObjectMapper objectMapper = new ObjectMapper();

        Map<String, Object> scanParametersMap = new HashMap<>();
        scanParametersMap.put(ApplicationConstants.GITLAB_TOKEN_KEY, TOKEN);

        BlackDuck blackDuck = new BlackDuck();
        blackDuck.setUrl("https://fake.blackduck.url");
        blackDuck.setToken(TOKEN);
        blackDuck.setAutomation(new Automation());
        blackDuck.getAutomation().setPrComment(true);

        String jsonStringForPrComment =
                "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\",\"automation\":{\"prComment\":true}},\"gitlab\":{\"user\":{\"token\":\"MDJDSROSVC56FAKEKEY\"},\"repository\":{\"branch\":{\"name\":\"fake-gitlab-branch\"},\"pull\":{\"number\":12},\"name\":\"fake-group/fake-gitlab-repo\"}}}}";

        try {
            Gitlab gitlabObject = gitlabRepositoryService.createGitlabObject(
                    scanParametersMap,
                    "fake-group/fake-gitlab-repo",
                    12,
                    "fake-gitlab-branch",
                    "https://gitlab.com/fake-group/fake-gitlab-repo.git",
                    true);
            String inputJsonPathForGitlabPrComment = scannerArgumentService.createBridgeInputJson(
                    scanParametersMap,
                    blackDuck,
                    gitlabObject,
                    true,
                    null,
                    null,
                    ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX,
                    null);

            JsonNode expectedJsonNode = objectMapper.readTree(jsonStringForPrComment);

            Path filePath = Paths.get(inputJsonPathForGitlabPrComment);
            String actualJsonString = new String(Files.readAllBytes(Paths.get(inputJsonPathForGitlabPrComment)));
            JsonNode actualJsonNode = objectMapper.readTree(actualJsonString);

            assertEquals(expectedJsonNode, actualJsonNode);
            Utility.removeFile(filePath.toString(), workspace, listenerMock);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void getCommandLineArgsForBlackDuckTest() throws PluginExceptionHandler {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.PRODUCT_KEY, "blackduck");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, "https://fake.blackduck.url");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, false);
        blackDuckParametersMap.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, true);

        Map<String, Boolean> installedDependencies = new HashMap<>();
        installedDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        List<String> commandLineArgs =
                scannerArgumentService.getCommandLineArgs(installedDependencies, blackDuckParametersMap, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY_WINDOWS).getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.BLACKDUCK_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.COVERITY_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.POLARIS_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.DIAGNOSTICS_OPTION);

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForCoverityTest() throws PluginExceptionHandler {
        Map<String, Object> coverityParameters = new HashMap<>();
        coverityParameters.put(ApplicationConstants.PRODUCT_KEY, "coverity");
        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, "https://fake.coverity.url");
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, "fake-user");
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, "fakeUserPassword");
        coverityParameters.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, true);

        Map<String, Boolean> installedDependencies = new HashMap<>();
        installedDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        List<String> commandLineArgs =
                scannerArgumentService.getCommandLineArgs(installedDependencies, coverityParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY_WINDOWS).getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.COVERITY_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.POLARIS_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.BLACKDUCK_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));
        assertEquals(commandLineArgs.get(5), BridgeParams.DIAGNOSTICS_OPTION);

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForPolarisTest() throws PluginExceptionHandler {
        Map<String, Object> polarisParameters = new HashMap<>();
        polarisParameters.put(ApplicationConstants.PRODUCT_KEY, "polaris");
        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, "https://fake.polaris.url");
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, "fake-token");
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, "Fake-application-name");
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");

        Map<String, Boolean> installedDependencies = new HashMap<>();
        installedDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        List<String> commandLineArgs =
                scannerArgumentService.getCommandLineArgs(installedDependencies, polarisParameters, workspace);
        scannerArgumentService.getCommandLineArgs(installedDependencies, polarisParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY_WINDOWS).getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.POLARIS_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.COVERITY_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.BLACKDUCK_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.POLARIS_INPUT_JSON_PREFIX.concat(".json")));

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void getCommandLineArgsForSrmTest() throws PluginExceptionHandler {
        Map<String, Object> srmParameters = new HashMap<>();
        srmParameters.put(ApplicationConstants.PRODUCT_KEY, "srm");
        srmParameters.put(ApplicationConstants.SRM_URL_KEY, "https://fake.srm.url");
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, "fake-api-key");
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, "SCA");
        srmParameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, "fake-project-name");
        srmParameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, "fake-project-id");

        Map<String, Boolean> installedDependencies = new HashMap<>();
        installedDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        List<String> commandLineArgs =
                scannerArgumentService.getCommandLineArgs(installedDependencies, srmParameters, workspace);
        scannerArgumentService.getCommandLineArgs(installedDependencies, srmParameters, workspace);

        if (getOSNameForTest().contains("win")) {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY_WINDOWS).getRemote());
        } else {
            assertEquals(
                    commandLineArgs.get(0),
                    workspace.child(ApplicationConstants.BRIDGE_BINARY).getRemote());
        }
        assertEquals(commandLineArgs.get(1), BridgeParams.STAGE_OPTION);
        assertEquals(commandLineArgs.get(2), BridgeParams.SRM_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.COVERITY_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.BLACKDUCK_STAGE);
        assertNotEquals(commandLineArgs.get(2), BridgeParams.POLARIS_STAGE);
        assertEquals(commandLineArgs.get(3), BridgeParams.INPUT_OPTION);
        assertTrue(
                Files.exists(Path.of(commandLineArgs.get(4))),
                String.format(
                        "File %s does not exist at the specified path.",
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void isPrCommentValueSetTest() {
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, true);
        assertTrue(scannerArgumentService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY, true);
        assertTrue(scannerArgumentService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        assertTrue(scannerArgumentService.isPrCommentValueSet(scanParameters));

        scanParameters.clear();
        assertFalse(scannerArgumentService.isPrCommentValueSet(scanParameters));
    }

    @Test
    public void removeTemporaryInputJsonTest() {
        String[] fileNames = {"file1.json", "file2.json"};
        List<String> inputJsonPath = new ArrayList<>();

        for (String fileName : fileNames) {
            Path filePath = Paths.get(getHomeDirectoryForTest(), fileName);
            String jsonContent = "{\"key\": \"value\"}";

            try {
                Files.write(filePath, jsonContent.getBytes());
                inputJsonPath.add(filePath.toString());
            } catch (IOException e) {
                System.err.println("Error creating file: " + filePath);
            }
        }

        scannerArgumentService.removeTemporaryInputJson(inputJsonPath);

        for (String path : inputJsonPath) {
            assertFalse(Files.exists(Paths.get(path)));
        }
    }

    public String getHomeDirectoryForTest() {
        return System.getProperty("user.home");
    }

    public String getOSNameForTest() {
        return System.getProperty("os.name").toLowerCase();
    }
}
