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

    public Boolean isBlackduck_prComment_enabled();

    public Boolean isBlackduck_prComment_enabled_temporary();

    public String getBlackduck_download_url();

    public Integer getBlackduck_search_depth();

    public String getBlackduck_config_path();

    public String getBlackduck_args();

    public String getCoverity_url();

    public String getCoverity_user();

    public String getCoverity_passphrase();

    public String getCoverity_project_name();

    public String getCoverity_stream_name();

    public String getCoverity_policy_view();

    public String getCoverity_install_directory();

    public Boolean isCoverity_automation_prcomment();

    public Boolean isCoverity_prComment_enabled();

    public Boolean isCoverity_prComment_enabled_temporary();

    public String getCoverity_build_command();

    public String getCoverity_clean_command();

    public String getCoverity_config_path();

    public String getCoverity_args();

    public String getCoverity_version();

    public Boolean isCoverity_local();

    public String getPolaris_server_url();

    public String getPolaris_access_token();

    public String getPolaris_application_name();

    public String getPolaris_project_name();

    public String getPolaris_assessment_types();

    public String getPolaris_triage();

    public String getPolaris_branch_name();

    public Boolean isPolaris_prComment_enabled();

    public Boolean isPolarisPrCommentEnabledActualValue();

    public String getPolaris_prComment_severities();

    public String getPolaris_branch_parent_name();

    public String getBitbucket_username();

    public Boolean isPolaris_reports_sarif_create();

    public String getPolaris_reports_sarif_file_path();

    public Boolean isPolaris_reports_sarif_groupSCAIssues();

    public String getPolaris_reports_sarif_severities();

    public String getPolaris_reports_sarif_issue_types();

    public Boolean isPolaris_reports_sarif_groupSCAIssues_temporary();

    public String getPolaris_assessment_mode();

    public String getPolaris_test_sca_type();

    public Integer getPolaris_sca_search_depth();

    public String getPolaris_sca_config_path();

    public String getPolaris_sca_args();

    public String getPolaris_sast_build_command();

    public String getPolaris_sast_clean_command();

    public String getPolaris_sast_config_path();

    public String getPolaris_sast_args();

    public String getProject_source_archive();

    public Boolean isProject_source_preserveSymLinks();

    public Boolean isProject_source_preserveSymLinks_actualValue();

    public String getProject_source_excludes();

    public String getProject_directory();

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

    public Boolean isReturn_status();

    public String getMark_build_status();
}
