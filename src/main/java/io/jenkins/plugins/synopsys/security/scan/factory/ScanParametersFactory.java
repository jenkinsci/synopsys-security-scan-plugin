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
import io.jenkins.plugins.synopsys.security.scan.extension.SecurityScan;
import io.jenkins.plugins.synopsys.security.scan.extension.global.ScannerGlobalConfig;
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
            SecurityScan securityScan, Map<String, Object> parametersMap, TaskListener listener)
            throws PluginExceptionHandler {
        String product = securityScan.getProduct();

        if (validateProduct(product, listener)) {
            parametersMap.put(
                    ApplicationConstants.PRODUCT_KEY,
                    securityScan.getProduct().trim().toUpperCase());

            parametersMap.putAll(prepareCoverityParametersMap(securityScan));
            parametersMap.putAll(preparePolarisParametersMap(securityScan));
            parametersMap.putAll(prepareBlackDuckParametersMap(securityScan));
            parametersMap.putAll(prepareSarifReportParametersMap(securityScan));

            if (!Utility.isStringNullOrBlank(securityScan.getBitbucket_token())) {
                parametersMap.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, securityScan.getBitbucket_token());
            }
            if (!Utility.isStringNullOrBlank(securityScan.getGitlab_token())) {
                parametersMap.put(ApplicationConstants.GITLAB_TOKEN_KEY, securityScan.getGitlab_token());
            }

            if (!Utility.isStringNullOrBlank(securityScan.getGithub_token())) {
                parametersMap.put(ApplicationConstants.GITHUB_TOKEN_KEY, securityScan.getGithub_token());
            }

            parametersMap.putAll(prepareBridgeParametersMap(securityScan));

            if (securityScan.isReturn_status() != null) {
                parametersMap.put(ApplicationConstants.RETURN_STATUS_KEY, securityScan.isReturn_status());
            }

            return parametersMap;
        } else {
            throw new PluginExceptionHandler(ErrorCode.INVALID_SECURITY_PRODUCT);
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
                    globalParameters,
                    ApplicationConstants.GITHUB_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getGithubCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.GITLAB_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getGitlabCredentialsId())
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

    public static Map<String, Object> prepareBlackDuckParametersMap(SecurityScan securityScan) {
        Map<String, Object> blackDuckParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_url())) {
            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_URL_KEY, securityScan.getBlackduck_url());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_token())) {
            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_TOKEN_KEY, securityScan.getBlackduck_token());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_install_directory())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY,
                    securityScan.getBlackduck_install_directory());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_scan_failure_severities())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY,
                    securityScan.getBlackduck_scan_failure_severities().toUpperCase());
        }

        if (securityScan.isBlackduckIntelligentScan() != null) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY, securityScan.isBlackduckIntelligentScan());
        }

        //        if (securityScan.isBlackduck_automation_fixpr() != null) {
        //            blackDuckParameters.put(ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY,
        // securityScan.isBlackduck_automation_fixpr());
        //        }

        if (securityScan.isBlackduck_automation_prcomment() != null) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY,
                    securityScan.isBlackduck_automation_prcomment());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_download_url())) {
            blackDuckParameters.put(
                    ApplicationConstants.BLACKDUCK_DOWNLOAD_URL_KEY, securityScan.getBlackduck_download_url());
        }

        return blackDuckParameters;
    }

    public static Map<String, Object> prepareCoverityParametersMap(SecurityScan securityScan) {
        Map<String, Object> coverityParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_url())) {
            coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, securityScan.getCoverity_url());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_user())) {
            coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, securityScan.getCoverity_user());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_passphrase())) {
            coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, securityScan.getCoverity_passphrase());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_project_name())) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_PROJECT_NAME_KEY, securityScan.getCoverity_project_name());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_stream_name())) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_STREAM_NAME_KEY, securityScan.getCoverity_stream_name());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_policy_view())) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_POLICY_VIEW_KEY, securityScan.getCoverity_policy_view());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_install_directory())) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY, securityScan.getCoverity_install_directory());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getCoverity_version())) {
            coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, securityScan.getCoverity_version());
        }

        if (securityScan.isCoverity_local() != null) {
            coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, securityScan.isCoverity_local());
        }

        if (securityScan.isCoverity_automation_prcomment() != null) {
            coverityParameters.put(
                    ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY,
                    securityScan.isCoverity_automation_prcomment());
        }

        return coverityParameters;
    }

    public static Map<String, Object> prepareBridgeParametersMap(SecurityScan securityScan) {
        Map<String, Object> bridgeParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(securityScan.getSynopsys_bridge_download_url())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL, securityScan.getSynopsys_bridge_download_url());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getSynopsys_bridge_download_version())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION,
                    securityScan.getSynopsys_bridge_download_version());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getSynopsys_bridge_install_directory())) {
            bridgeParameters.put(
                    ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY,
                    securityScan.getSynopsys_bridge_install_directory());
        }

        if (securityScan.isInclude_diagnostics() != null) {
            bridgeParameters.put(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, securityScan.isInclude_diagnostics());
        }

        if (securityScan.isNetwork_airgap() != null) {
            bridgeParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, securityScan.isNetwork_airgap());
        }

        return bridgeParameters;
    }

    public static Map<String, Object> preparePolarisParametersMap(SecurityScan securityScan) {
        Map<String, Object> polarisParametersMap = new HashMap<>();

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_server_url())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, securityScan.getPolaris_server_url());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_access_token())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, securityScan.getPolaris_access_token());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_application_name())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, securityScan.getPolaris_application_name());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_project_name())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_PROJECT_NAME_KEY, securityScan.getPolaris_project_name());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_assessment_types())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, securityScan.getPolaris_assessment_types());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_triage())) {
            polarisParametersMap.put(ApplicationConstants.POLARIS_TRIAGE_KEY, securityScan.getPolaris_triage());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_branch_name())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_BRANCH_NAME_KEY, securityScan.getPolaris_branch_name());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_test_sca_type())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, securityScan.getPolaris_test_sca_type());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_branch_parent_name())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, securityScan.getPolaris_branch_parent_name());
        }

        if (securityScan.isPolaris_prComment_enabled() != null) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, securityScan.isPolaris_prComment_enabled());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_prComment_severities())) {
            polarisParametersMap.put(
                    ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, securityScan.getPolaris_prComment_severities());
        }

        return polarisParametersMap;
    }

    public static Map<String, Object> prepareSarifReportParametersMap(SecurityScan securityScan) {
        Map<String, Object> sarifParameters = new HashMap<>();

        if (securityScan.isBlackduck_reports_sarif_create() != null) {
            sarifParameters.put(
                    ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY,
                    securityScan.isBlackduck_reports_sarif_create());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_reports_sarif_file_path())) {
            sarifParameters.put(
                    ApplicationConstants.BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY,
                    securityScan.getBlackduck_reports_sarif_file_path());
        }

        if (securityScan.isBlackduck_reports_sarif_groupSCAIssues_temporary() != null) {
            sarifParameters.put(
                    ApplicationConstants.BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY,
                    securityScan.isBlackduck_reports_sarif_groupSCAIssues_temporary());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getBlackduck_reports_sarif_severities())) {
            sarifParameters.put(
                    ApplicationConstants.BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY,
                    securityScan.getBlackduck_reports_sarif_severities());
        }

        if (securityScan.isPolaris_reports_sarif_create() != null) {
            sarifParameters.put(
                    ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY,
                    securityScan.isPolaris_reports_sarif_create());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_reports_sarif_file_path())) {
            sarifParameters.put(
                    ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY,
                    securityScan.getPolaris_reports_sarif_file_path());
        }

        if (securityScan.isPolaris_reports_sarif_groupSCAIssues_temporary() != null) {
            sarifParameters.put(
                    ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY,
                    securityScan.isPolaris_reports_sarif_groupSCAIssues_temporary());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_reports_sarif_severities())) {
            sarifParameters.put(
                    ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY,
                    securityScan.getPolaris_reports_sarif_severities());
        }

        if (!Utility.isStringNullOrBlank(securityScan.getPolaris_reports_sarif_issue_types())) {
            sarifParameters.put(
                    ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY,
                    securityScan.getPolaris_reports_sarif_issue_types());
        }

        return sarifParameters;
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
            logger.error("Invalid Synopsys Security Product");
            logger.info(
                    "Supported values for Synopsys security products: " + Arrays.toString(SecurityProduct.values()));
        }

        return isValid;
    }
}
