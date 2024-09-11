package io.jenkins.plugins.synopsys.security.scan.global;

import java.util.HashMap;
import java.util.Map;

public class ExceptionMessages {
    public static final String NULL_WORKSPACE = "Detect cannot be executed when the workspace is null";

    public static Map<Integer, String> getExitCodeToMessageMap() {
        Map<Integer, String> exitCodeToMessage = new HashMap<>();

        exitCodeToMessage.put(ErrorCode.SCAN_SUCCESSFUL, "Synopsys Security Scan execution is successful");

        exitCodeToMessage.put(ErrorCode.BRIDGE_UNDEFINED_ERROR, "Undefined error, check error logs");
        exitCodeToMessage.put(ErrorCode.BRIDGE_ADAPTER_ERROR, "Error from adapter");
        exitCodeToMessage.put(ErrorCode.BRIDGE_SHUTDOWN_FAILED, "Failed to shutdown the Bridge");
        exitCodeToMessage.put(ErrorCode.BRIDGE_BUILD_BREAK, "The config option 'bridge.break' has been set to true");
        exitCodeToMessage.put(ErrorCode.BRIDGE_STARTUP_FAILED, "Bridge initialization failed");

        exitCodeToMessage.put(ErrorCode.INVALID_SECURITY_PRODUCT, "Invalid Synopsys Security Product");
        exitCodeToMessage.put(ErrorCode.INVALID_BLACKDUCK_PARAMETERS, "Invalid BlackDuck parameters");
        exitCodeToMessage.put(ErrorCode.INVALID_COVERITY_PARAMETERS, "Invalid Coverity parameters");
        exitCodeToMessage.put(ErrorCode.INVALID_POLARIS_PARAMETERS, "Invalid Polaris parameters");
        exitCodeToMessage.put(ErrorCode.INVALID_SRM_PARAMETERS, "Invalid SRM parameters");
        exitCodeToMessage.put(ErrorCode.INVALID_BRIDGE_DOWNLOAD_PARAMETERS, "Bridge download parameters are not valid");
        exitCodeToMessage.put(ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_FAILED, "Synopsys Bridge download failed");
        exitCodeToMessage.put(
                ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_FAILED_AND_WONT_RETRY,
                "Synopsys Bridge download failed and will not retry to download");
        exitCodeToMessage.put(ErrorCode.SYNOPSYS_BRIDGE_UNZIPPING_FAILED, "Synopsys Bridge unzipping failed");
        exitCodeToMessage.put(
                ErrorCode.SYNOPSYS_BRIDGE_NOT_FOUND_IN_PROVIDED_PATH,
                "Synopsys Bridge could not be found in provided path");
        exitCodeToMessage.put(ErrorCode.NO_BITBUCKET_TOKEN_FOUND, "No Bitbucket token found");
        exitCodeToMessage.put(ErrorCode.NO_GITHUB_TOKEN_FOUND, "No GitHub token found");
        exitCodeToMessage.put(ErrorCode.NO_GITLAB_TOKEN_FOUND, "No GitLab token found");
        exitCodeToMessage.put(ErrorCode.INVALID_GITHUB_URL, "Invalid GitHub repository URL");
        exitCodeToMessage.put(ErrorCode.INVALID_GITLAB_URL, "Invalid GitLab repository URL");
        exitCodeToMessage.put(ErrorCode.UNDEFINED_PLUGIN_ERROR, "Undefined plugin error");
        exitCodeToMessage.put(
                ErrorCode.REQUIRED_BRANCH_SOURCE_PLUGIN_NOT_INSTALLED,
                "Necessary 'Branch Source Plugin' is not installed in Jenkins instance");

        return exitCodeToMessage;
    }

    public static String getErrorMessage(int exitCode, String undefinedErrorMessage) {
        String errorMessage = null;
        Map<Integer, String> exitCodeToMessage = ExceptionMessages.getExitCodeToMessageMap();
        if (exitCodeToMessage.containsKey(exitCode)) {
            if (exitCode == ErrorCode.SCAN_SUCCESSFUL) {
                errorMessage = exitCodeToMessage.get(exitCode);
            } else if (exitCode == ErrorCode.UNDEFINED_PLUGIN_ERROR) {
                errorMessage = "Workflow failed! Exit code " + exitCode
                        + ": " + exitCodeToMessage.get(exitCode) + " - "
                        + undefinedErrorMessage;
            } else {
                errorMessage = "Workflow failed! Exit code " + exitCode + ": " + exitCodeToMessage.get(exitCode);
            }
        }
        return errorMessage;
    }
}
