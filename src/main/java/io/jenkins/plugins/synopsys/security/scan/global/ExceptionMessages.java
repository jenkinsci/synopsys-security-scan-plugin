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
        exitCodeToMessage.put(ErrorCode.BRIDGE_BUILD_BREAK, "The config option bridge.break has been set to true");
        exitCodeToMessage.put(ErrorCode.BRIDGE_STARTUP_FAILED, "Bridge initialization failed");

        exitCodeToMessage.put(ErrorCode.PARAMETER_VALIDATION_FAILED, "Parameter validation failed");

        return exitCodeToMessage;
    }
}
