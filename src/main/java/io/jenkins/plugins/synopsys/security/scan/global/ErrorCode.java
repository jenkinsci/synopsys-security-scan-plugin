package io.jenkins.plugins.synopsys.security.scan.global;

public class ErrorCode {
    // Bridge specific error codes
    public static final int BRIDGE_UNDEFINED_ERROR = 1;
    public static final int BRIDGE_ADAPTER_ERROR = 2;
    public static final int BRIDGE_SHUTDOWN_FAILED = 3;
    public static final int BRIDGE_BUILD_BREAK = 8;
    public static final int BRIDGE_STARTUP_FAILED = 9;

    // Plugin specific error codes
    public static final int PARAMETER_VALIDATION_FAILED = 31;
    public static final int SYNOPSYS_BRIDGE_DOWNLOAD_OR_INSTALLATION_FAILED = 32;
    public static final int SYNOPSYS_BRIDGE_EXECUTABLE_NOT_FOUND = 33;
    public static final int SCM_TOKEN_NOT_FOUND = 34;
    public static final int SCM_URL_VALIDATION_FAILED = 35;
    public static final int UNDEFINED_PLUGIN_ERROR = 36;
}
