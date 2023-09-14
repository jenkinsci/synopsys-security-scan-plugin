/*
 * synopsys-security-scan-plugin
 *
 * Copyright (c) 2023 Synopsys, Inc.
 *
 * Use subject to the terms and conditions of the Synopsys End User Software License and Maintenance Agreement. All rights reserved worldwide.
 */
package com.synopsys.integration.jenkins.scan.service;

import com.synopsys.integration.jenkins.scan.ScanPipelineCommands;
import com.synopsys.integration.jenkins.scan.SecurityScanner;
import com.synopsys.integration.jenkins.scan.extension.global.ScannerGlobalConfig;
import com.synopsys.integration.jenkins.scan.extension.pipeline.SecurityScanStep;
import com.synopsys.integration.jenkins.scan.global.ApplicationConstants;
import com.synopsys.integration.jenkins.scan.global.ExceptionMessages;
import com.synopsys.integration.jenkins.scan.global.Utility;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.util.HashMap;
import java.util.Map;
import jenkins.model.GlobalConfiguration;

public class ScanCommandsFactory {
    private final TaskListener listener;
    private final EnvVars envVars;
    private final FilePath workspace;

    private ScanCommandsFactory(TaskListener listener, EnvVars envVars, FilePath workspace) throws AbortException {
        this.listener = listener;
        this.envVars = envVars;

        if (workspace == null) {
            throw new AbortException(ExceptionMessages.NULL_WORKSPACE);
        }
        this.workspace = workspace;
    }

    public static ScanPipelineCommands createPipelineCommand(Run<?, ?> run, TaskListener listener,
                                                             EnvVars envVars, Launcher launcher,
                                                             Node node, FilePath workspace) {
        return new ScanPipelineCommands(
            new SecurityScanner(run, listener, launcher, workspace, envVars,
                new ScannerArgumentService(listener, envVars, workspace)), workspace, listener);
    }

    public static Map<String, Object> preparePipelineParametersMap(SecurityScanStep scanStep, FilePath workspace, TaskListener listener) {
        Map<String, Object> parametersMap = new HashMap<>(getGlobalConfigurationValues(workspace, listener));

        parametersMap.put(ApplicationConstants.SYNOPSYS_SECURITY_PLATFORM_KEY, scanStep.getSynopsys_security_platform().trim().toUpperCase());

        parametersMap.putAll(prepareCoverityParametersMap(scanStep));
        parametersMap.putAll(preparePolarisParametersMap(scanStep));
        parametersMap.putAll(prepareBlackDuckParametersMap(scanStep));

        if (!Utility.isStringNullOrBlank(scanStep.getBitbucket_token())) {
            parametersMap.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, scanStep.getBitbucket_token());
        }

        parametersMap.putAll(prepareBridgeParametersMap(scanStep));

        return parametersMap;
    }

    private static Map<String, Object> getGlobalConfigurationValues(FilePath workspace, TaskListener listener) {
        Map<String, Object> globalParameters = new HashMap<>();
        ScannerGlobalConfig config = GlobalConfiguration.all().get(ScannerGlobalConfig.class);

        if (config != null) {

            String synopsysBridgeDownloadUrl = getSynopsysBridgeDownloadUrlBasedOnAgentOS(workspace, listener,
                    config.getSynopsysBridgeDownloadUrlForMac(), config.getSynopsysBridgeDownloadUrlForLinux(),
                    config.getSynopsysBridgeDownloadUrlForWindows());

            if (!Utility.isStringNullOrBlank(config.getBlackDuckUrl())) {
                globalParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_URL_KEY, config.getBlackDuckUrl());
            }
            if (!Utility.isStringNullOrBlank(config.getBlackDuckApiToken())) {
                globalParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_API_TOKEN_KEY, config.getBlackDuckApiToken());
            }
            if (!Utility.isStringNullOrBlank(config.getBlackDuckInstallationPath())) {
                globalParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_INSTALL_DIRECTORY_KEY, config.getBlackDuckInstallationPath());
            }

            if (!Utility.isStringNullOrBlank(config.getCoverityConnectUrl())) {
                globalParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_URL_KEY, config.getCoverityConnectUrl());
            }
            if (!Utility.isStringNullOrBlank(config.getCoverityConnectUserName())) {
                globalParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_NAME_KEY, config.getCoverityConnectUserName());
            }
            if (!Utility.isStringNullOrBlank(config.getCoverityConnectUserPassword())) {
                globalParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_PASSWORD_KEY, config.getCoverityConnectUserPassword());
            }
            if (!Utility.isStringNullOrBlank(config.getCoverityInstallationPath())) {
                globalParameters.put(ApplicationConstants.BRIDGE_COVERITY_INSTALL_DIRECTORY_KEY, config.getCoverityInstallationPath());
            }

            if (!Utility.isStringNullOrBlank(config.getBitbucketToken())) {
                globalParameters.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, config.getBitbucketToken());
            }

            if(!Utility.isStringNullOrBlank(synopsysBridgeDownloadUrl)) {
                globalParameters.put(ApplicationConstants.BRIDGE_DOWNLOAD_URL, synopsysBridgeDownloadUrl);
            }

            if (!Utility.isStringNullOrBlank(config.getSynopsysBridgeInstallationPath())) {
                globalParameters.put(ApplicationConstants.BRIDGE_INSTALLATION_PATH, config.getSynopsysBridgeInstallationPath());
            }

            if (!Utility.isStringNullOrBlank(config.getSynopsysBridgeVersion())) {
                globalParameters.put(ApplicationConstants.BRIDGE_DOWNLOAD_VERSION, config.getSynopsysBridgeVersion());
            }

            if (!Utility.isStringNullOrBlank(config.getPolarisServerUrl())) {
                globalParameters.put(ApplicationConstants.BRIDGE_POLARIS_SERVER_URL_KEY, config.getPolarisServerUrl());
            }

            if (!Utility.isStringNullOrBlank(config.getPolarisAccessToken())) {
                globalParameters.put(ApplicationConstants.BRIDGE_POLARIS_ACCESS_TOKEN_KEY, config.getPolarisAccessToken());
            }
        }

        return globalParameters;
    }

    private static Map<String, Object> prepareBlackDuckParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> blackDuckParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getBridge_blackduck_url())) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_URL_KEY, scanStep.getBridge_blackduck_url());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_blackduck_api_token())) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_API_TOKEN_KEY, scanStep.getBridge_blackduck_api_token());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_blackduck_install_directory())) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_INSTALL_DIRECTORY_KEY, scanStep.getBridge_blackduck_install_directory());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_blackduck_scan_failure_severities())) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY, scanStep.getBridge_blackduck_scan_failure_severities().toUpperCase());
        }
        if (scanStep.isBridge_blackduck_scan_full() != null) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_SCAN_FULL_KEY, scanStep.isBridge_blackduck_scan_full());
        }
//        if (scanStep.isBridge_blackduck_automation_fixpr() != null) {
//            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_AUTOMATION_FIXPR_KEY, scanStep.isBridge_blackduck_automation_fixpr());
//        }
        if (scanStep.isBridge_blackduck_automation_prcomment() != null) {
            blackDuckParameters.put(ApplicationConstants.BRIDGE_BLACKDUCK_AUTOMATION_PRCOMMENT_KEY, scanStep.isBridge_blackduck_automation_prcomment());
        }

        return blackDuckParameters;
    }

    private static Map<String, Object> prepareCoverityParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> coverityParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_url())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_URL_KEY, scanStep.getBridge_coverity_connect_url());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_user_name())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_NAME_KEY, scanStep.getBridge_coverity_connect_user_name());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_user_password())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_PASSWORD_KEY, scanStep.getBridge_coverity_connect_user_password());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_project_name())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_PROJECT_NAME_KEY, scanStep.getBridge_coverity_connect_project_name());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_stream_name())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_STREAM_NAME_KEY, scanStep.getBridge_coverity_connect_stream_name());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_connect_policy_view())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_CONNECT_POLICY_VIEW_KEY, scanStep.getBridge_coverity_connect_policy_view());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_install_directory())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_INSTALL_DIRECTORY_KEY, scanStep.getBridge_coverity_install_directory());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_coverity_version())) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_VERSION_KEY, scanStep.getBridge_coverity_version());
        }
        if (scanStep.isBridge_coverity_local() != null) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_LOCAL_KEY, scanStep.isBridge_coverity_local());
        }
        if (scanStep.isBridge_coverity_automation_prcomment() != null) {
            coverityParameters.put(ApplicationConstants.BRIDGE_COVERITY_AUTOMATION_PRCOMMENT_KEY, scanStep.isBridge_coverity_automation_prcomment());
        }

        return coverityParameters;
    }

    private static Map<String, Object> prepareBridgeParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> bridgeParameters = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getBridge_download_url())) {
          bridgeParameters.put(ApplicationConstants.BRIDGE_DOWNLOAD_URL, scanStep.getBridge_download_url());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_download_version())) {
          bridgeParameters.put(ApplicationConstants.BRIDGE_DOWNLOAD_VERSION, scanStep.getBridge_download_version());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getSynopsys_bridge_path())) {
          bridgeParameters.put(ApplicationConstants.BRIDGE_INSTALLATION_PATH, scanStep.getSynopsys_bridge_path());
        }
        if(scanStep.isBridge_include_diagnostics() != null) {
            bridgeParameters.put(ApplicationConstants.BRIDGE_INCLUDE_DIAGNOSTICS_KEY, scanStep.isBridge_include_diagnostics());
        }

        return bridgeParameters;
    }

    private static Map<String, Object> preparePolarisParametersMap(SecurityScanStep scanStep) {
        Map<String, Object> polarisParametersMap = new HashMap<>();

        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_serverurl())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_SERVER_URL_KEY, scanStep.getBridge_polaris_serverurl());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_accesstoken())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_ACCESS_TOKEN_KEY, scanStep.getBridge_polaris_accesstoken());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_application_name())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_APPLICATION_NAME_KEY, scanStep.getBridge_polaris_application_name());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_project_name())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_PROJECT_NAME_KEY, scanStep.getBridge_polaris_project_name());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_assessment_types())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_ASSESSMENT_TYPES_KEY, scanStep.getBridge_polaris_assessment_types());
        }
        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_triage())) {
            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_TRIAGE_KEY, scanStep.getBridge_polaris_triage());
        }
//        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_branch_name())) {
//            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_BRANCH_NAME_KEY, scanStep.getBridge_polaris_branch_name());
//        }
//        if (!Utility.isStringNullOrBlank(scanStep.getBridge_polaris_branch_parent_name())) {
//            polarisParametersMap.put(ApplicationConstants.BRIDGE_POLARIS_BRANCH_PARENT_NAME_KEY, scanStep.getBridge_polaris_branch_parent_name());
//        }

        return polarisParametersMap;
    }

    private static String getSynopsysBridgeDownloadUrlBasedOnAgentOS(FilePath workspace, TaskListener listener,
                                                                     String synopsysBridgeDownloadUrlForMac,
                                                                     String synopsysBridgeDownloadUrlForLinux,
                                                                     String synopsysBridgeDownloadUrlForWindows) {
        String agentOs = Utility.getAgentOs(workspace, listener);
        if (agentOs.contains("mac")) {
            return synopsysBridgeDownloadUrlForMac;
        } else if (agentOs.contains("linux")) {
            return synopsysBridgeDownloadUrlForLinux;
        }
        else {
            return synopsysBridgeDownloadUrlForWindows;
        }
    }

}
