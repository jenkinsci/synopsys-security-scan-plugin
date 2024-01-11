package io.jenkins.plugins.synopsys.security.scan.global;

import java.util.HashMap;
import java.util.Map;

public class ExceptionMessages {
    public static final String NULL_WORKSPACE = "Detect cannot be executed when the workspace is null";

    public static String scannerFailedWithExitCode(int exitCode) {
        return "Synopsys Security Scan failed with unknown exit code " + exitCode;
    }

    public static String scannerFailureMessage(String message) {
        return "Synopsys Security Scan failed!! " + message;
    }

    public static Map<Integer, String> getExitCodeToMessageMap() {
        Map<Integer, String> exitCodeToMessage = new HashMap<>();

        exitCodeToMessage.put(ErrorCode.BRIDGE_UNDEFINED_ERROR, "Undefined error, check error logs");
        exitCodeToMessage.put(ErrorCode.BRIDGE_ADAPTER_ERROR, "Error from adapter");
        exitCodeToMessage.put(ErrorCode.BRIDGE_SHUTDOWN_FAILED, "Failed to shutdown the Bridge");
        exitCodeToMessage.put(ErrorCode.BRIDGE_BUILD_BREAK, "The config option 'bridge.break' has been set to true");
        exitCodeToMessage.put(ErrorCode.BRIDGE_STARTUP_FAILED, "Bridge initialization failed");

        exitCodeToMessage.put(ErrorCode.PARAMETER_VALIDATION_FAILED, "Scan parameter validation failed");
        exitCodeToMessage.put(ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_OR_INSTALLATION_FAILED, "Synopsys bridge download or installation failed");
        exitCodeToMessage.put(ErrorCode.SYNOPSYS_BRIDGE_EXECUTABLE_NOT_FOUND, "Synopsys bridge executable not found in installation path");
        exitCodeToMessage.put(ErrorCode.SCM_TOKEN_NOT_FOUND, "SCM token not found");
        exitCodeToMessage.put(ErrorCode.SCM_URL_VALIDATION_FAILED, "SCM URL validation failed");
        exitCodeToMessage.put(ErrorCode.UNDEFINED_PLUGIN_ERROR, "Undefined plugin error, check error logs");

        return exitCodeToMessage;
    }
}
