package io.jenkins.plugins.synopsys.security.scan.extension;

public interface SecurityScan {
    public String getProduct();

    public String getBlackduck_url();

    public String getBlackduck_token();

    public String getBlackduck_install_directory();

    public Boolean isBlackduck_scan_full();

    public Boolean isBlackduckIntelligentScan();

    public String getBlackduck_scan_failure_severities();

    public String getBlackduck_download_url();

    public Integer getBlackduck_search_depth();

    public String getBlackduck_config_path();

    public String getBlackduck_args();

    public String getBlackduck_execution_path();

    public String getCoverity_url();

    public String getCoverity_user();

    public String getCoverity_passphrase();

    public String getCoverity_project_name();

    public String getCoverity_stream_name();

    public String getCoverity_policy_view();

    public String getCoverity_install_directory();

    public String getCoverity_build_command();

    public String getCoverity_clean_command();

    public String getCoverity_config_path();

    public String getCoverity_args();

    public String getCoverity_version();

    public Boolean isCoverity_local();

    public Boolean isCoverity_waitForScan();

    public Boolean isCoverity_waitForScan_actualValue();

    public String getCoverity_execution_path();

    public String getPolaris_server_url();

    public String getPolaris_access_token();

    public String getPolaris_application_name();

    public String getPolaris_project_name();

    public String getPolaris_assessment_types();

    public String getPolaris_triage();

    public String getPolaris_branch_name();

    public String getPolaris_prComment_severities();

    public String getPolaris_branch_parent_name();

    public String getPolaris_test_sca_type();

    public String getBitbucket_username();

    public Boolean isPolaris_reports_sarif_create();

    public String getPolaris_reports_sarif_file_path();

    public Boolean isPolaris_reports_sarif_groupSCAIssues();

    public String getPolaris_reports_sarif_severities();

    public String getPolaris_reports_sarif_issue_types();

    public Boolean isPolaris_reports_sarif_groupSCAIssues_temporary();

    public Boolean isPolaris_waitForScan();

    public Boolean isPolaris_waitForScan_actualValue();

    public String getPolaris_assessment_mode();

    public String getProject_source_archive();

    public Boolean isProject_source_preserveSymLinks();

    public Boolean isProject_source_preserveSymLinks_actualValue();

    public String getProject_source_excludes();

    public String getProject_directory();

    public String getSrm_url();

    public String getSrm_apikey();

    public String getSrm_project_name();

    public String getSrm_project_id();

    public String getSrm_assessment_types();

    public String getSrm_branch_name();

    public String getSrm_branch_parent();

    public Boolean isSrm_waitForScan();

    public Boolean isSrm_waitForScan_actualValue();

    public String getBitbucket_token();

    public String getGithub_token();

    public String getGitlab_token();

    public String getSynopsys_bridge_download_url();

    public String getSynopsys_bridge_download_version();

    public String getSynopsys_bridge_install_directory();

    public Boolean isInclude_diagnostics();

    public Boolean isNetwork_airgap();

    public Boolean isBlackduck_reports_sarif_create();

    public String getBlackduck_reports_sarif_file_path();

    public Boolean isBlackduck_reports_sarif_groupSCAIssues();

    public String getBlackduck_reports_sarif_severities();

    public Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary();

    public Boolean isBlackduck_waitForScan();

    public Boolean isBlackduck_waitForScan_actualValue();

    public String getMark_build_status();
}
