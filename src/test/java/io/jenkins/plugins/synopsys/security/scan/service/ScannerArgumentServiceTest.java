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
import io.jenkins.plugins.synopsys.security.scan.input.BridgeInput;
import io.jenkins.plugins.synopsys.security.scan.input.bitbucket.Bitbucket;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.github.Github;
import io.jenkins.plugins.synopsys.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.github.GithubRepositoryService;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class ScannerArgumentServiceTest {
    private Bitbucket bitBucket;
    private ScannerArgumentService scannerArgumentService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
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

        scannerArgumentService = new ScannerArgumentService(listenerMock, envVarsMock, workspace);
    }

    @Test
    void createBlackDuckInputJsonTest() {
        BlackDuck blackDuck = new BlackDuck();
        blackDuck.setUrl("https://fake.blackduck.url");
        blackDuck.setToken(TOKEN);

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                blackDuck, bitBucket, false, null, null, ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX);
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

        Bitbucket bitbucketObject =
                BitbucketRepositoryService.createBitbucketObject("https://bitbucket.org", TOKEN, 12, "test", "abc");

        try {
            String jsonStringNonPrCommentOrFixPr =
                    "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":"
                            + "\"MDJDSROSVC56FAKEKEY\",\"install\":{},\"scan\":{\"failure\":{}},\"automation\":{}}}}";

            String inputJsonPathForNonFixPr = scannerArgumentService.createBridgeInputJson(
                    blackDuck, bitbucketObject, false, null, null, ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX);
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
                    "{\"data\":{\"blackduck\":{\"url\":\"https://fake.blackduck.url\",\"token\":\"MDJDSROSVC56FAKEKEY\""
                            + ",\"install\":{},\"scan\":{\"failure\":{}},\"automation\":{}},\"bitbucket\": { \"api\": "
                            + "{ \"url\": \"https://bitbucket.org\", \"token\": \"MDJDSROSVC56FAKEKEY\" }, \"project\": "
                            + "{ \"repository\": { \"pull\": { \"number\": 12 }, \"name\": \"test\" }, "
                            + "\"key\": \"abc\" } }}}";
            String inputJsonPathForPrComment = scannerArgumentService.createBridgeInputJson(
                    blackDuck, bitbucketObject, true, null, null, ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX);
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

        scannerArgumentService.setScmObject(bridgeInput, bitbucket);
        Mockito.verify(bridgeInput).setBitbucket(bitbucket);

        scannerArgumentService.setScmObject(bridgeInput, github);
        Mockito.verify(bridgeInput).setGithub(github);
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
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");

        String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                coverity, bitBucket, false, null, null, ApplicationConstants.COVERITY_INPUT_JSON_PREFIX);
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
                + "\"project\":{\"name\":\"fake-repo\"},\"stream\":{\"name\":\"fake-repo-fake-branch\"},"
                + "\"policy\":{}},\"install\":{},\"automation\":{},\"local\":false},"
                + "\"github\":{\"user\":{\"token\":\"MDJDSROSVC56FAKEKEY\"},\"repository\":{\"name\":\"fake-repo\""
                + ",\"owner\":{\"name\":\"fake-owner\"},\"pull\":{\"number\":1},\"branch\":{\"name\":"
                + "\"fake-branch\"}},\"host\":{\"url\":\"\"}}}}";

        Coverity coverity = new Coverity();
        coverity.getConnect().setUrl("https://fake.coverity.url");
        coverity.getConnect().getUser().setName("fake-user");
        coverity.getConnect().getUser().setPassword("fakeUserPassword");

        try {
            Github github = githubRepositoryService.createGithubObject(
                    scanParametersMap,
                    "fake-repo",
                    "fake-owner",
                    1,
                    "fake-branch",
                    "https://github.com/user/fake-repo.git",
                    true);
            String inputJsonPath = scannerArgumentService.createBridgeInputJson(
                    coverity, github, true, null, null, ApplicationConstants.COVERITY_INPUT_JSON_PREFIX);
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
    public void getCommandLineArgsForBlackDuckTest() throws PluginExceptionHandler {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.PRODUCT_KEY, "blackduck");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_URL_KEY, "https://fake.blackduck.url");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, false);
        blackDuckParametersMap.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, true);

        List<String> commandLineArgs = scannerArgumentService.getCommandLineArgs(blackDuckParametersMap, workspace);

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

        List<String> commandLineArgs = scannerArgumentService.getCommandLineArgs(coverityParameters, workspace);

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

        List<String> commandLineArgs = scannerArgumentService.getCommandLineArgs(polarisParameters, workspace);

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
                        ApplicationConstants.COVERITY_INPUT_JSON_PREFIX.concat(".json")));

        Utility.removeFile(commandLineArgs.get(4), workspace, listenerMock);
    }

    @Test
    public void isFixPrOrPrCommentValueSetTest() {
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY, true);
        assertTrue(scannerArgumentService.isFixPrOrPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, true);
        assertTrue(scannerArgumentService.isFixPrOrPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY, true);
        assertTrue(scannerArgumentService.isFixPrOrPrCommentValueSet(scanParameters));

        scanParameters.clear();
        scanParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY, true);
        scanParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, true);
        assertTrue(scannerArgumentService.isFixPrOrPrCommentValueSet(scanParameters));

        scanParameters.clear();
        assertFalse(scannerArgumentService.isFixPrOrPrCommentValueSet(scanParameters));
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
