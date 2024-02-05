package io.jenkins.plugins.synopsys.security.scan.global;

import java.util.HashMap;
import java.util.Map;

public class ExceptionMessages {
    public static final String NULL_WORKSPACE = "Detect cannot be executed when the workspace is null";

    public static String scannerFailedWithExitCode(int exitCode) {
        return "Synopsys Security Scan failed with exit code " + exitCode;
    }

    public static String scannerFailureMessage(String message) {
        return "Synopsys Security Scan failed!! " + message;
    }

    public static Map<Integer, String> bridgeErrorMessages() {
        Map<Integer, String> exitCodeToMessage = new HashMap<>();

        exitCodeToMessage.put(1, "Workflow failed! Exit Code: 1 Undefined error, check error logs");
        exitCodeToMessage.put(2, "Workflow failed! Exit Code: 2 Error from adapter");
        exitCodeToMessage.put(3, "Workflow failed! Exit Code: 3 Failed to shutdown the Bridge");
        exitCodeToMessage.put(8, "Workflow failed! Exit Code: 8 The config option bridge.break has been set to true");
        exitCodeToMessage.put(9, "Workflow failed! Exit Code: 9 Bridge initialization failed");
        exitCodeToMessage.put(
                10,
                "Workflow failed! Exit Code: 10 Please install necessary 'Branch Source Plugin' in your jenkins instance");

        return exitCodeToMessage;
    }
}
