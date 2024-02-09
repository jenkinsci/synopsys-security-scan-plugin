package io.jenkins.plugins.synopsys.security.scan.global;

public class ErrorCode {
    // Bridge specific error codes
    public static final int SCAN_SUCCESSFUL = 0;
    public static final int BRIDGE_UNDEFINED_ERROR = 1;
    public static final int BRIDGE_ADAPTER_ERROR = 2;
    public static final int BRIDGE_SHUTDOWN_FAILED = 3;
    public static final int BRIDGE_BUILD_BREAK = 8;
    public static final int BRIDGE_STARTUP_FAILED = 9;

    // Plugin specific error codes
    public static final int INVALID_SECURITY_PRODUCT = 101;
    public static final int INVALID_BLACKDUCK_PARAMETERS = 102;
    public static final int INVALID_COVERITY_PARAMETERS = 103;
    public static final int INVALID_POLARIS_PARAMETERS = 104;
    public static final int INVALID_BRIDGE_DOWNLOAD_PARAMETERS = 105;
    public static final int SYNOPSYS_BRIDGE_DOWNLOAD_FAILED = 106;
    public static final int SYNOPSYS_BRIDGE_DOWNLOAD_FAILED_AND_WONT_RETRY = 107;
    public static final int SYNOPSYS_BRIDGE_UNZIPPING_FAILED = 108;
    public static final int SYNOPSYS_BRIDGE_NOT_FOUND_IN_PROVIDED_PATH = 109;
    public static final int NO_BITBUCKET_TOKEN_FOUND = 110;
    public static final int NO_GITHUB_TOKEN_FOUND = 111;
    public static final int NO_GITLAB_TOKEN_FOUND = 112;
    public static final int INVALID_GITHUB_URL = 113;
    public static final int INVALID_GITLAB_URL = 114;
    public static final int REQUIRED_BRANCH_SOURCE_PLUGIN_NOT_INSTALLED = 115;
    public static final int UNDEFINED_PLUGIN_ERROR = 999;
}
