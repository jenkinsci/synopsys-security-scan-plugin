package io.jenkins.plugins.synopsys.security.scan.global;

public class ApplicationConstants {
    public static final String DISPLAY_NAME = "Synopsys Security Scan";
    public static final String PIPELINE_NAME = "synopsys_scan";
    public static final String BRIDGE_ARTIFACTORY_URL =
            "https://sig-repo.synopsys.com/artifactory/bds-integrations-release/com/synopsys/integration/synopsys-bridge";
    public static final String SYNOPSYS_BRIDGE_RUN_COMMAND = "synopsys-bridge";
    public static final String SYNOPSYS_BRIDGE_RUN_COMMAND_WINDOWS = "synopsys-bridge.exe";
    public static final String SYNOPSYS_BRIDGE_LATEST_VERSION = "latest";
    public static final String BRIDGE_DOWNLOAD_FILE_PATH = "/tmp/synopsys-security-scan";
    public static final String BRIDGE_ZIP_FILE_FORMAT = "bridge.zip";
    public static final String PLATFORM_LINUX = "linux64";
    public static final String PLATFORM_WINDOWS = "win64";
    public static final String PLATFORM_MAC_ARM = "macos_arm";
    public static final String PLATFORM_MACOSX = "macosx";
    public static final String MAC_ARM_COMPATIBLE_BRIDGE_VERSION = "2.1.0";
    public static final String DEFAULT_DIRECTORY_NAME = "synopsys-bridge";
    public static final String BRIDGE_DIAGNOSTICS_DIRECTORY = ".bridge";
    public static final int BRIDGE_DOWNLOAD_MAX_RETRIES = 3;
    public static final int INTERVAL_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS = 10000;
    public static final String ALL_FILES_WILDCARD_SYMBOL = "**";
    public static final String BRIDGE_BINARY = "synopsys-bridge";
    public static final String BRIDGE_BINARY_WINDOWS = "synopsys-bridge.exe";
    public static final String EXTENSIONS_DIRECTORY = "extensions";
    public static final String VERSION_FILE = "versions.txt";
    public static final String NOT_AVAILABLE = "NA";
    public static final String ENV_JOB_NAME_KEY = "JOB_NAME";
    public static final String ENV_CHANGE_ID_KEY = "CHANGE_ID";
    public static final String ENV_BRANCH_NAME_KEY = "BRANCH_NAME";

    public static final String PRODUCT_KEY = "product";
    public static final String BLACKDUCK_URL_KEY = "blackduck_url";
    public static final String BLACKDUCK_TOKEN_KEY = "blackduck_token";
    public static final String BLACKDUCK_INSTALL_DIRECTORY_KEY = "blackduck_install_directory";
    public static final String BLACKDUCK_SCAN_FULL_KEY = "blackduck_scan_full";
    public static final String BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY = "blackduck_scan_failure_severities";
    public static final String BLACKDUCK_AUTOMATION_FIXPR_KEY = "blackduck_automation_fixpr";
    public static final String BLACKDUCK_AUTOMATION_PRCOMMENT_KEY = "blackduck_automation_prcomment";
    public static final String BLACKDUCK_DOWNLOAD_URL_KEY = "blackduck_download_url";

    public static final String COVERITY_URL_KEY = "coverity_url";
    public static final String COVERITY_USER_KEY = "coverity_user";
    public static final String COVERITY_PASSPHRASE_KEY = "coverity_passphrase";
    public static final String COVERITY_PROJECT_NAME_KEY = "coverity_project_name";
    public static final String COVERITY_STREAM_NAME_KEY = "coverity_stream_name";
    public static final String COVERITY_POLICY_VIEW_KEY = "coverity_policy_view";
    public static final String COVERITY_INSTALL_DIRECTORY_KEY = "coverity_install_directory";
    public static final String COVERITY_AUTOMATION_PRCOMMENT_KEY = "coverity_automation_prcomment";
    public static final String COVERITY_VERSION_KEY = "coverity_version";
    public static final String COVERITY_LOCAL_KEY = "coverity_local";

    public static final String POLARIS_SERVER_URL_KEY = "polaris_server_url";
    public static final String POLARIS_ACCESS_TOKEN_KEY = "polaris_access_token";
    public static final String POLARIS_APPLICATION_NAME_KEY = "polaris_application_name";
    public static final String POLARIS_PROJECT_NAME_KEY = "polaris_project_name";
    public static final String POLARIS_ASSESSMENT_TYPES_KEY = "polaris_assessment_types";
    public static final String POLARIS_TRIAGE_KEY = "polaris_triage";
    public static final String POLARIS_BRANCH_NAME_KEY = "polaris_branch_name";
    public static final String POLARIS_BRANCH_PARENT_NAME_KEY = "polaris_branch_parent_name";

    public static final String INCLUDE_DIAGNOSTICS_KEY = "include_diagnostics";

    public static final String NETWORK_AIRGAP_KEY = "network_airgap";

    public static final String BITBUCKET_TOKEN_KEY = "bitbucket_token";
    public static final String GITHUB_TOKEN_KEY = "github_token";

    public static final String SYNOPSYS_BRIDGE_DOWNLOAD_URL = "synopsys_bridge_download_url";
    public static final String SYNOPSYS_BRIDGE_DOWNLOAD_VERSION = "synopsys_bridge_download_version";
    public static final String SYNOPSYS_BRIDGE_INSTALL_DIRECTORY = "synopsys_bridge_install_directory";

    public static final String BLACKDUCK_INPUT_JSON_PREFIX = "blackduck_input";
    public static final String COVERITY_INPUT_JSON_PREFIX = "coverity_input";
    public static final String POLARIS_INPUT_JSON_PREFIX = "polaris_input";

    public static final String HTTPS_PROXY = "HTTPS_PROXY";
    public static final String HTTP_PROXY = "HTTP_PROXY";
    public static final String NO_PROXY = "NO_PROXY";

    public static final String BLACKDUCK_AUTH_API = "api/tokens/authenticate";
    public static final String POLARIS_PORTFOLIO_API = "api/portfolio/portfolios";
    public static final String COVERITY_VIEWS_API = "api/v2/views";
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    public static final String BRANCH_NAME = "BRANCH_NAME";
    public static final String GIT_URL = "GIT_URL";
}
