package io.jenkins.plugins.synopsys.security.scan.global;

public class LogMessages {
    public static final String ASTERISKS =
            "******************************************************************************";
    public static final String DASHES =
            "------------------------------------------------------------------------------------";
    public static final String INVALID_SYNOPSYS_BRIDGE_DOWNLOAD_URL = "Invalid Synopsys Bridge download URL: %s";
    public static final String FAILED_TO_FETCH_PLUGINS_DEFAULT_INSTALLATION_PATH =
            "Failed to fetch plugin's default installation path: %s";
    public static final String BLACKDUCK_PARAMETER_VALIDATION_FAILED = "BlackDuck parameters are not valid";
    public static final String COVERITY_PARAMETER_VALIDATION_FAILED = "Coverity parameters are not valid";
    public static final String POLARIS_PARAMETER_VALIDATION_FAILED = "Polaris parameters are not valid";
    public static final String NO_BITBUCKET_TOKEN_FOUND = "PrComment is set true but no Bitbucket token found!";
    public static final String NO_GITHUB_TOKEN_FOUND = "PrComment is set true but no Github token found!";
    public static final String INVALID_BRIDGE_DOWNLOAD_PARAMETERS = "Bridge download parameters are not valid";
    public static final String EMPTY_BRIDGE_DOWNLOAD_URL_PROVIDED = "The provided Bridge download URL is empty";
    public static final String INVALID_BRIDGE_DOWNLOAD_URL_PROVIDED =
            "The provided Bridge download URL is not valid: %s";
    public static final String INVALID_BRIDGE_DOWNLOAD_VERSION_PROVIDED =
            "The provided Bridge download version is not valid: %s";
    public static final String EXCEPTION_OCCURRED_WHILE_INVOKING_SYNOPSYS_BRIDGE =
            "An exception occurred while invoking synopsys-bridge from the plugin: %s";
    public static final String EXCEPTION_OCCURRED_WHILE_DOWNLOADING_OR_INSTALLING_SYNOPSYS_BRIDGE =
            "An exception occurred while installing/downloading synopsys-bridge: %s";
    public static final String INVALID_SYNOPSYS_SECURITY_PRODUCT = "Invalid Synopsys Security Product!";
    public static final String SYNOPSYS_BRIDGE_DOWNLOAD_FAILED = "Synopsys bridge download failed!";
    public static final String JENKINS_INSTANCE_MISSING_WARNING =
            "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.";
}
