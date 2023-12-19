package io.jenkins.plugins.synopsys.security.scan.extension;

public interface SecurityScan {
    public String getProduct();

    public String getBlackduck_url();
    public String getBlackduck_token();
    public String getBlackduck_install_directory();
    public Boolean isBlackduck_scan_full();
    public Boolean isBlackduckIntelligentScan();
    public String getBlackduck_scan_failure_severities();
    public Boolean isBlackduck_automation_prcomment();
    public String getBlackduck_download_url();

    public String getCoverity_url();
    public String getCoverity_user();
    public String getCoverity_passphrase();
    public String getCoverity_project_name();
    public String getCoverity_stream_name();
    public String getCoverity_policy_view();
    public String getCoverity_install_directory();
    public Boolean isCoverity_automation_prcomment();
    public String getCoverity_version();
    public Boolean isCoverity_local();

    public String getPolaris_server_url();
    public String getPolaris_access_token();
    public String getPolaris_application_name();
    public String getPolaris_project_name();
    public String getPolaris_assessment_types();
    public String getPolaris_triage();
    public String getPolaris_branch_name();

    public String getBitbucket_token();
    public String getSynopsys_bridge_download_url();
    public String getSynopsys_bridge_download_version();
    public String getSynopsys_bridge_install_directory();
    public Boolean isInclude_diagnostics();
    public Boolean isNetwork_airgap();

}