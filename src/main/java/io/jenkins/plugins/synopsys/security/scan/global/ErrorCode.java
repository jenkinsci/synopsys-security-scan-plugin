package io.jenkins.plugins.synopsys.security.scan.global;

public class ErrorCode {
    //Bridge specific error codes
    public static int BRIDGE_UNDEFINED_ERROR = 1;
    public static int BRIDGE_ADAPTER_ERROR = 2;
    public static int BRIDGE_SHUTDOWN_FAILED = 3;
    public static int BRIDGE_BUILD_BREAK = 8;
    public static int BRIDGE_STARTUP_FAILED = 9;

    //Plugin specific error codes
    public static int PARAMETER_VALIDATION_FAILED = 31;
    public static int BRIDGE_DOWNLOAD_OR_INSTALLATION_FAILED = 32;
    public static int BRIDGE_EXECUTABLE_NOT_FOUND = 33;
    public static int SCM_TOKEN_NOT_FOUND = 34;
    public static int SCM_URL_VALIDATION_FAILED = 35;
    public static int UNKNOWN_PLUGIN_ERROR = 36;
}
