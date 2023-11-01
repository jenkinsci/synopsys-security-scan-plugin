package io.jenkins.plugins.synopsys.security.scan.factory;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.PluginParametersHandler;
import io.jenkins.plugins.synopsys.security.scan.SecurityScanner;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.extension.global.ScannerGlobalConfig;
import io.jenkins.plugins.synopsys.security.scan.extension.pipeline.SecurityScanStep;
import io.jenkins.plugins.synopsys.security.scan.global.*;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import io.jenkins.plugins.synopsys.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.synopsys.security.scan.service.ScannerArgumentService;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import jenkins.model.GlobalConfiguration;

public class ScanParametersFactory {
    private final EnvVars envVars;
    private final FilePath workspace;

    public ScanParametersFactory(EnvVars envVars, FilePath workspace) throws AbortException {
        this.envVars = envVars;

        if (workspace == null) {
            throw new AbortException(ExceptionMessages.NULL_WORKSPACE);
        }
        this.workspace = workspace;
    }

    public static PluginParametersHandler createPipelineCommand(
            Run<?, ?> run, TaskListener listener, EnvVars envVars, Launcher launcher, Node node, FilePath workspace) {
        return new PluginParametersHandler(
                new SecurityScanner(
                        run,
                        listener,
                        launcher,
                        workspace,
                        envVars,
                        new ScannerArgumentService(listener, envVars, workspace)),
                workspace,
                envVars,
                listener);
    }

    public static Map<String, Object> preparePipelineParametersMap(
            SecurityScanStep scanStep, Map<String, Object> parametersMap, TaskListener listener)
            throws PluginExceptionHandler {
        String product = scanStep.getProduct();

        if (validateProduct(product, listener)) {
            parametersMap.put(
                    ApplicationConstants.PRODUCT_KEY,
                    scanStep.getProduct().trim().toUpperCase());

            parametersMap.putAll(prepareCoverityParametersMap(scanStep));
            parametersMap.putAll(preparePolarisParametersMap(scanStep));
            parametersMap.putAll(prepareBlackDuckParametersMap(scanStep));

            if (!Utility.isStringNullOrBlank(scanStep.getBitbucket_token())) {
                parametersMap.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, scanStep.getBitbucket_token());
            }
            parametersMap.putAll(prepareBridgeParametersMap(scanStep));

            return parametersMap;
        } else {
            throw new PluginExceptionHandler(LogMessages.INVALID_SYNOPSYS_SECURITY_PRODUCT);
        }
    }

    public static Map<String, Object> getGlobalConfigurationValues(FilePath workspace, TaskListener listener) {
        Map<String, Object> globalParameters = new HashMap<>();
        ScannerGlobalConfig config = GlobalConfiguration.all().get(ScannerGlobalConfig.class);

        ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

        if (config != null) {
            String synopsysBridgeDownloadUrl = getSynopsysBridgeDownloadUrlBasedOnAgentOS(
                    workspace,
                    listener,
                    config.getSynopsysBridgeDownloadUrlForMac(),
                    config.getSynopsysBridgeDownloadUrlForLinux(),
                    config.getSynopsysBridgeDownloadUrlForWindows());

            addParameterIfNotBlank(globalParameters, ApplicationConstants.BLACKDUCK_URL_KEY, config.getBlackDuckUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BLACKDUCK_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getBlackDuckCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY,
                    config.getBlackDuckInstallationPath());
            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.COVERITY_URL_KEY, config.getCoverityConnectUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_USER_KEY,
                    scanCredentialsHelper
                            .getUsernameByCredentialsId(config.getCoverityCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_PASSPHRASE_KEY,
                    scanCredentialsHelper
                            .getPasswordByCredentialsId(config.getCoverityCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY,
                    config.getCoverityInstallationPath());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BITBUCKET_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getBitbucketCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL, synopsysBridgeDownloadUrl);
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY,
                    config.getSynopsysBridgeInstallationPath());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION,
                    config.getSynopsysBridgeVersion());
            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.POLARIS_SERVER_URL_KEY, config.getPolarisServerUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getPolarisCredentialsId())
                            .orElse(null));
        }

        return globalParameters;
    }

    public static void addParameterIfNotBlank(Map<String, Object> parameters, String key, String value) {
        if (!Utility.isStringNullOrBlank(value)) {
            parameters.put(key, value);
        }
    }

    public static Map<String, Object> prepareBlackDuckParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> blackDuckParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getBlackduck_url())) {
            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_URL_KEY, scanStep.getBlackduck_url());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getBlackduck_token())) {
            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, scanStep.getBlackduck_token());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getBlackduck_install_directory())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY, scanStep.getBlackduck_install_directory());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getBlackduck_scan_failure_severities())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY,
                    scanStep.getBlackduck_scan_failure_severities().toUpperCase());
        }

        if (scanStep.isBlackduckIntelligentScan() != null) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY, scanStep.isBlackduckIntelligentScan());
        }

        //        if (scanStep.isBlackduck_automation_fixpr() != null) {
        //            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY,
        // scanStep.isBlackduck_automation_fixpr());
        //        }

        if (scanStep.isBlackduck_automation_prcomment() != null) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY,
                    scanStep.isBlackduck_automation_prcomment());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getBlackduck_download_url())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_DOWNLOAD_URL_KEY, scanStep.getBlackduck_download_url());
        }

        return blackDuckParameters;
    }

    public static Map<String, Object> prepareCoverityParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> coverityParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_url())) {
            coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, scanStep.getCoverity_url());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_user())) {
            coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, scanStep.getCoverity_user());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_passphrase())) {
            coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, scanStep.getCoverity_passphrase());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_project_name())) {
            coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, scanStep.getCoverity_project_name());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_stream_name())) {
            coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, scanStep.getCoverity_stream_name());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_policy_view())) {
            coverityParameters.put(ApplicationConstants.COVERITY_POLICY_VIEW_KEY, scanStep.getCoverity_policy_view());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_install_directory())) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY, scanStep.getCoverity_install_directory());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getCoverity_version())) {
            coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, scanStep.getCoverity_version());
        }

        if (scanStep.isCoverity_local() != null) {
            coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, scanStep.isCoverity_local());
        }

        if (scanStep.isCoverity_automation_prcomment() != null) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY, scanStep.isCoverity_automation_prcomment());
        }

        return coverityParameters;
    }

    public static Map<String, Object> prepareBridgeParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> bridgeParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getSynopsys_bridge_download_url())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL, scanStep.getSynopsys_bridge_download_url());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getSynopsys_bridge_download_version())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION,
                    scanStep.getSynopsys_bridge_download_version());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getSynopsys_bridge_install_directory())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY,
                    scanStep.getSynopsys_bridge_install_directory());
        }

        if (scanStep.isInclude_diagnostics() != null) {
            bridgeParameters.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, scanStep.isInclude_diagnostics());
        }

        if (scanStep.isNetwork_airgap() != null) {
            bridgeParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, scanStep.isNetwork_airgap());
        }

        return bridgeParameters;
    }

    public static Map<String, Object> preparePolarisParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> polarisParametersMap = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_server_url())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, scanStep.getPolaris_server_url());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_access_token())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, scanStep.getPolaris_access_token());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_application_name())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, scanStep.getPolaris_application_name());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_project_name())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, scanStep.getPolaris_project_name());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_assessment_types())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, scanStep.getPolaris_assessment_types());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_triage())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_TRIAGE_KEY, scanStep.getPolaris_triage());
        }

        if (!Utility.isStringNullOrBlank(scanStep.getPolaris_branch_name())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, scanStep.getPolaris_branch_name());
        }

        //        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_branch_parent_name())) {
        //            polarisParametersMap.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY,
        // scanStep.getBridge_polaris_branch_parent_name());
        //        }

        return polarisParametersMap;
    }

    public static String getSynopsysBridgeDownloadUrlBasedOnAgentOS(
            FilePath workspace,
            TaskListener listener,
            String synopsysBridgeDownloadUrlForMac,
            String synopsysBridgeDownloadUrlForLinux,
            String synopsysBridgeDownloadUrlForWindows) {
        String agentOs = Utility.getAgentOs(workspace, listener);
        if (agentOs.contains("mac")) {
            return synopsysBridgeDownloadUrlForMac;
        } else if (agentOs.contains("linux")) {
            return synopsysBridgeDownloadUrlForLinux;
        } else {
            return synopsysBridgeDownloadUrlForWindows;
        }
    }

    public static boolean validateProduct(String product, TaskListener listener) {
        LoggerWrapper logger = new LoggerWrapper(listener);

        boolean isValid = !Utility.isStringNullOrBlank(product)
                && Arrays.stream(product.split(","))
                        .map(String::trim)
                        .map(String::toUpperCase)
                        .allMatch(p -> p.equals(SecurityProduct.BLACKDUCK.name())
                                || p.equals(SecurityProduct.POLARIS.name())
                                || p.equals(SecurityProduct.COVERITY.name()));

        if (!isValid) {
            logger.error(LogMessages.INVALID_SYNOPSYS_SECURITY_PRODUCT);
            logger.info("Supported Synopsys Security Products: " + Arrays.toString(SecurityProduct.values()));
        }

        return isValid;
    }
}
