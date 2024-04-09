package io.jenkins.plugins.synopsys.security.scan.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.BridgeParams;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.synopsys.security.scan.input.BridgeInput;
import io.jenkins.plugins.synopsys.security.scan.input.NetworkAirGap;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Parent;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.report.File;
import io.jenkins.plugins.synopsys.security.scan.input.report.Issue;
import io.jenkins.plugins.synopsys.security.scan.input.report.Reports;
import io.jenkins.plugins.synopsys.security.scan.input.report.Sarif;
import io.jenkins.plugins.synopsys.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.synopsys.security.scan.input.scm.github.Github;
import io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.synopsys.security.scan.service.scan.ScanParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck.BlackDuckParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.polaris.PolarisParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scm.SCMRepositoryService;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class ScannerArgumentService {
    private final TaskListener listener;
    private final EnvVars envVars;
    private final FilePath workspace;
    private static final String DATA_KEY = "data";
    private final LoggerWrapper logger;

    public ScannerArgumentService(TaskListener listener, EnvVars envVars, FilePath workspace) {
        this.listener = listener;
        this.envVars = envVars;
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
    }

    public List<String> getCommandLineArgs(
            Map<String, Boolean> installedBranchSourceDependencies,
            Map<String, Object> scanParameters,
            FilePath bridgeInstallationPath)
            throws PluginExceptionHandler {
        List<String> commandLineArgs = new ArrayList<>();

        commandLineArgs.add(getBridgeRunCommand(bridgeInstallationPath));

        commandLineArgs.addAll(getSecurityProductSpecificCommands(installedBranchSourceDependencies, scanParameters));

        if (Objects.equals(scanParameters.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY), true)) {
            commandLineArgs.add(BridgeParams.DIAGNOSTICS_OPTION);
        }

        return commandLineArgs;
    }

    private String getBridgeRunCommand(FilePath bridgeInstallationPath) {
        String os = Utility.getAgentOs(workspace, listener);

        if (os.contains("win")) {
            return bridgeInstallationPath
                    .child(ApplicationConstants.SYNOPSYS_BRIDGE_RUN_COMMAND_WINDOWS)
                    .getRemote();
        } else {
            return bridgeInstallationPath
                    .child(ApplicationConstants.SYNOPSYS_BRIDGE_RUN_COMMAND)
                    .getRemote();
        }
    }

    private List<String> getSecurityProductSpecificCommands(
            Map<String, Boolean> installedBranchSourceDependencies, Map<String, Object> scanParameters)
            throws PluginExceptionHandler {
        ScanParametersService scanParametersService = new ScanParametersService(listener, envVars);
        Set<String> securityProducts = scanParametersService.getSynopsysSecurityProducts(scanParameters);

        boolean fixPrOrPrComment = isFixPrOrPrCommentValueSet(scanParameters);

        SCMRepositoryService scmRepositoryService = new SCMRepositoryService(listener, envVars);
        Object scmObject = null;

        String jobType = Utility.jenkinsJobType(envVars);
        if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            scmObject = scmRepositoryService.fetchSCMRepositoryDetails(
                    installedBranchSourceDependencies, scanParameters, fixPrOrPrComment);
        }

        List<String> scanCommands = new ArrayList<>();

        NetworkAirGap networkAirGap = null;
        Sarif sarif = null;
        if (scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)) {
            Boolean isNetworkAirgap = (Boolean) scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY);
            networkAirGap = new NetworkAirGap();
            networkAirGap.setAirgap(isNetworkAirgap);
        }

        if ((scanParameters.containsKey(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY)
                        || scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY))
                && envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) == null) {
            sarif = prepareSarifObject(securityProducts, scanParameters);
        }

        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())) {
            BlackDuckParametersService blackDuckParametersService = new BlackDuckParametersService(listener);
            BlackDuck blackDuck = blackDuckParametersService.prepareBlackDuckObjectForBridge(scanParameters);

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.BLACKDUCK_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(createBridgeInputJson(
                    blackDuck,
                    scmObject,
                    fixPrOrPrComment,
                    networkAirGap,
                    sarif,
                    ApplicationConstants.BLACKDUCK_INPUT_JSON_PREFIX));
        }
        if (securityProducts.contains(SecurityProduct.COVERITY.name())) {
            CoverityParametersService coverityParametersService = new CoverityParametersService(listener, envVars);
            Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(scanParameters);

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.COVERITY_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(createBridgeInputJson(
                    coverity,
                    scmObject,
                    fixPrOrPrComment,
                    networkAirGap,
                    sarif,
                    ApplicationConstants.COVERITY_INPUT_JSON_PREFIX));
        }
        if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            PolarisParametersService polarisParametersService = new PolarisParametersService(listener, envVars);
            Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(scanParameters);

            if (polaris.getBranch().getParent() == null) {
                String defaultParentBranchName = envVars.get(ApplicationConstants.PARENT_BRANCH_NAME);
                if (defaultParentBranchName != null) {
                    Parent parent = new Parent();
                    parent.setName(defaultParentBranchName);
                    polaris.getBranch().setParent(parent);
                }
            }

            scanCommands.add(BridgeParams.STAGE_OPTION);
            scanCommands.add(BridgeParams.POLARIS_STAGE);
            scanCommands.add(BridgeParams.INPUT_OPTION);
            scanCommands.add(createBridgeInputJson(
                    polaris,
                    scmObject,
                    fixPrOrPrComment,
                    networkAirGap,
                    sarif,
                    ApplicationConstants.POLARIS_INPUT_JSON_PREFIX));
        }

        return scanCommands;
    }

    public String createBridgeInputJson(
            Object scanObject,
            Object scmObject,
            boolean fixPrOrPrComment,
            NetworkAirGap networkAirGap,
            Sarif sarif,
            String jsonPrefix) {
        BridgeInput bridgeInput = new BridgeInput();

        setScanObject(bridgeInput, scanObject, scmObject, sarif);

        if (fixPrOrPrComment) {
            setScmObject(bridgeInput, scmObject);
        }

        if (networkAirGap != null) {
            bridgeInput.setNetworkAirGap(networkAirGap);
        }

        Map<String, Object> inputJsonMap = new HashMap<>();
        inputJsonMap.put(DATA_KEY, bridgeInput);

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        String jsonPath = null;
        try {
            String inputJson = mapper.writeValueAsString(inputJsonMap);
            jsonPath = writeInputJsonToFile(inputJson, jsonPrefix);
        } catch (Exception e) {
            logger.error("An exception occurred while creating input.json file: " + e.getMessage());
        }

        return jsonPath;
    }

    private void setScanObject(BridgeInput bridgeInput, Object scanObject, Object scmObject, Sarif sarifObject) {

        if (scanObject instanceof BlackDuck) {
            BlackDuck blackDuck = (BlackDuck) scanObject;
            if (sarifObject != null) {
                blackDuck.setReports(new Reports());
                blackDuck.getReports().setSarif(sarifObject);
            }
            bridgeInput.setBlackDuck(blackDuck);
        } else if (scanObject instanceof Coverity) {
            Coverity coverity = (Coverity) scanObject;
            if (scmObject != null) {
                setCoverityProjectNameAndStreamName(coverity, scmObject);
            }
            bridgeInput.setCoverity(coverity);
        } else if (scanObject instanceof Polaris) {
            Polaris polaris = (Polaris) scanObject;
            if (sarifObject != null) {
                polaris.setReports(new Reports());
                polaris.getReports().setSarif(sarifObject);
            }
            bridgeInput.setPolaris(polaris);
        }
    }

    private void setCoverityProjectNameAndStreamName(Coverity coverity, Object scmObject) {
        String repositoryName = getRepositoryName(scmObject);
        String branchName = envVars.get(ApplicationConstants.ENV_BRANCH_NAME_KEY);

        if (Utility.isStringNullOrBlank(coverity.getConnect().getProject().getName()) && repositoryName != null) {
            coverity.getConnect().getProject().setName(repositoryName);
        }
        if (Utility.isStringNullOrBlank(coverity.getConnect().getStream().getName())
                && repositoryName != null
                && branchName != null) {
            coverity.getConnect().getStream().setName(repositoryName.concat("-").concat(branchName));
        }
    }

    private String getRepositoryName(Object scmObject) {
        if (scmObject instanceof Bitbucket) {
            Bitbucket bitbucket = (Bitbucket) scmObject;
            return bitbucket.getProject().getRepository().getName();
        } else if (scmObject instanceof Github) {
            Github github = (Github) scmObject;
            return github.getRepository().getName();
        } else if (scmObject instanceof Gitlab) {
            Gitlab gitlab = (Gitlab) scmObject;
            return gitlab.getRepository().getName();
        }

        return null;
    }

    public void setScmObject(BridgeInput bridgeInput, Object scmObject) {
        if (scmObject instanceof Bitbucket) {
            bridgeInput.setBitbucket((Bitbucket) scmObject);
        } else if (scmObject instanceof Github) {
            bridgeInput.setGithub((Github) scmObject);
        } else if (scmObject instanceof Gitlab) {
            bridgeInput.setGitlab((Gitlab) scmObject);
        }
    }

    public String writeInputJsonToFile(String inputJson, String jsonPrefix) {
        String inputJsonPath = null;

        try {
            FilePath parentWorkspacePath = workspace.getParent();
            if (parentWorkspacePath != null) {
                FilePath tempFile = parentWorkspacePath.createTempFile(jsonPrefix, ".json");
                tempFile.write(inputJson, StandardCharsets.UTF_8.name());
                inputJsonPath = tempFile.getRemote();
            } else {
                logger.error("Failed to create json file in workspace parent path");
            }
        } catch (Exception e) {
            logger.error("An exception occurred while writing into json file: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        return inputJsonPath;
    }

    public boolean isFixPrOrPrCommentValueSet(Map<String, Object> scanParameters) {
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY), true)) {
            return true;
        } else if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY), true)) {
            return true;
        } else if (scanParameters.containsKey(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY), true)) {
            return true;
        } else if (scanParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)
                && Objects.equals(scanParameters.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY), true)) {
            return true;
        }
        return false;
    }

    public void removeTemporaryInputJson(List<String> commandLineArgs) {
        for (String arg : commandLineArgs) {
            if (arg.endsWith(".json")) {
                Utility.removeFile(arg, workspace, listener);
            }
        }
    }

    public Sarif prepareSarifObject(Set<String> securityProducts, Map<String, Object> scanParameters) {
        Sarif sarif = new Sarif();

        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())) {
            handleBlackDuck(scanParameters, sarif);
            return sarif;

        } else if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            handlePolaris(scanParameters, sarif);
            return sarif;
        }
        return null;
    }

    private void handleBlackDuck(Map<String, Object> scanParameters, Sarif sarif) {
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY)) {
            Boolean isReports_sarif_create =
                    (Boolean) scanParameters.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY);
            sarif.setCreate(isReports_sarif_create);
        }
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY)) {
            String reports_sarif_file_path =
                    (String) scanParameters.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY);
            if (reports_sarif_file_path != null) {
                sarif.setFile(new File());
                sarif.getFile().setPath(reports_sarif_file_path);
            }
        }
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY)) {
            String reports_sarif_severities =
                    (String) scanParameters.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY);
            List<String> severities = new ArrayList<>();
            String[] reports_sarif_severitiesInput =
                    reports_sarif_severities.toUpperCase().split(",");

            addArrayElementsToList(reports_sarif_severitiesInput, severities);
            if (!severities.isEmpty()) {
                sarif.setSeverities(severities);
            }
        }
        if (scanParameters.containsKey(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY)) {
            Boolean reports_sarif_groupSCAIssues =
                    (Boolean) scanParameters.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY);
            sarif.setGroupSCAIssues(reports_sarif_groupSCAIssues);
        }
    }

    private void handlePolaris(Map<String, Object> scanParameters, Sarif sarif) {
        if (scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY)) {
            Boolean isReports_sarif_create =
                    (Boolean) scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY);
            sarif.setCreate(isReports_sarif_create);
        }
        if (scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY)) {
            String reports_sarif_file_path =
                    (String) scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY);
            if (reports_sarif_file_path != null) {
                sarif.setFile(new File());
                sarif.getFile().setPath(reports_sarif_file_path);
            }
        }
        if (scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY)) {
            String reports_sarif_severities =
                    (String) scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY);
            List<String> severities = new ArrayList<>();
            String[] reports_sarif_severitiesInput =
                    reports_sarif_severities.toUpperCase().split(",");

            addArrayElementsToList(reports_sarif_severitiesInput, severities);
            if (!severities.isEmpty()) {
                sarif.setSeverities(severities);
            }
        }
        if (scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY)) {
            Boolean reports_sarif_groupSCAIssues =
                    (Boolean) scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY);
            sarif.setGroupSCAIssues(reports_sarif_groupSCAIssues);
        }
        if (scanParameters.containsKey(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY)) {
            String reports_sarif_issue_types =
                    (String) scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY);
            List<String> issueTypes = new ArrayList<>();
            String[] reports_sarif_issue_typesInput =
                    reports_sarif_issue_types.toUpperCase().split(",");

            addArrayElementsToList(reports_sarif_issue_typesInput, issueTypes);
            if (!issueTypes.isEmpty()) {
                sarif.setIssue(new Issue());
                sarif.getIssue().setTypes(issueTypes);
            }
        }
    }

    private void addArrayElementsToList(String[] array, List<String> list) {
        for (String item : array) {
            list.add(item.trim());
        }
    }
}
