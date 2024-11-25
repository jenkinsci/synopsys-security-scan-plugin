package io.jenkins.plugins.synopsys.security.scan.extension.freestyle;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.*;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.exception.ScannerException;
import io.jenkins.plugins.synopsys.security.scan.extension.SecurityScan;
import io.jenkins.plugins.synopsys.security.scan.factory.ScanParametersFactory;
import io.jenkins.plugins.synopsys.security.scan.global.*;
import io.jenkins.plugins.synopsys.security.scan.global.enums.BuildStatus;
import io.jenkins.plugins.synopsys.security.scan.global.enums.SecurityProduct;
import java.util.Map;
import jenkins.tasks.SimpleBuildStep;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class SecurityScanFreestyle extends Builder implements SecurityScan, FreestyleScan, SimpleBuildStep {
    private String product;
    private String blackduck_url;
    private transient String blackduck_token;
    private transient String github_token;
    private transient String gitlab_token;
    private String blackduck_install_directory;
    private Boolean blackduck_scan_full;
    private Boolean blackduckIntelligentScan;
    private String blackduck_scan_failure_severities;
    private String blackduck_download_url;
    private Boolean blackduck_reports_sarif_create;
    private String blackduck_reports_sarif_file_path;
    private Boolean blackduck_reports_sarif_groupSCAIssues;
    private String blackduck_reports_sarif_severities;
    private Boolean blackduck_reports_sarif_groupSCAIssues_temporary;
    private Boolean blackduck_waitForScan;
    private Boolean blackduck_waitForScan_actualValue;
    private Integer blackduck_search_depth;
    private String blackduck_config_path;
    private String blackduck_args;
    private String blackduck_execution_path;

    private String coverity_url;
    private String coverity_user;
    private transient String coverity_passphrase;
    private String coverity_project_name;
    private String coverity_stream_name;
    private String coverity_policy_view;
    private String coverity_install_directory;
    private String coverity_version;
    private Boolean coverity_local;
    private Boolean coverity_waitForScan;
    private Boolean coverity_waitForScan_actualValue;
    private String coverity_build_command;
    private String coverity_clean_command;
    private String coverity_config_path;
    private String coverity_args;
    private String coverity_execution_path;

    private String polaris_server_url;
    private transient String polaris_access_token;
    private String polaris_application_name;
    private String polaris_project_name;
    private String polaris_assessment_types;
    private String polaris_triage;
    private String polaris_branch_name;
    private String polaris_branch_parent_name;
    private String polaris_prComment_severities;
    private Boolean polaris_reports_sarif_create;
    private String polaris_reports_sarif_file_path;
    private String polaris_reports_sarif_issue_types;
    private Boolean polaris_reports_sarif_groupSCAIssues;
    private String polaris_reports_sarif_severities;
    private Boolean polaris_reports_sarif_groupSCAIssues_temporary;
    private Boolean polaris_waitForScan;
    private Boolean polaris_waitForScan_actualValue;
    private String project_source_archive;
    private String polaris_assessment_mode;
    private String project_source_excludes;
    private Boolean project_source_preserveSymLinks;
    private Boolean project_source_preserveSymLinks_actualValue;
    private String project_directory;
    private String polaris_test_sca_type;
    private String coverity_project_directory;
    private String blackduck_project_directory;
    private String polaris_project_directory;
    private Integer polaris_sca_search_depth;
    private String polaris_sca_config_path;
    private String polaris_sca_args;
    private String polaris_sast_build_command;
    private String polaris_sast_clean_command;
    private String polaris_sast_config_path;
    private String polaris_sast_args;

    private String srm_url;
    private transient String srm_apikey;
    private String srm_assessment_types;
    private String srm_project_name;
    private String srm_project_id;
    private String srm_branch_name;
    private String srm_branch_parent;
    private Boolean srm_waitForScan;
    private Boolean srm_waitForScan_actualValue;
    private String srm_project_directory;
    private Integer srm_sca_search_depth;
    private String srm_sca_config_path;
    private String srm_sca_args;
    private String srm_sast_build_command;
    private String srm_sast_clean_command;
    private String srm_sast_config_path;
    private String srm_sast_args;

    private String bitbucket_username;
    private transient String bitbucket_token;

    private String synopsys_bridge_download_url;
    private String synopsys_bridge_download_version;
    private String synopsys_bridge_install_directory;
    private Boolean include_diagnostics;
    private Boolean network_airgap;

    private String mark_build_status;

    @DataBoundConstructor
    public SecurityScanFreestyle() {
        // this block is kept empty intentionally
    }

    public String getProduct() {
        return product;
    }

    public String getBlackduck_url() {
        return blackduck_url;
    }

    public String getBlackduck_token() {
        return blackduck_token;
    }

    public String getBlackduck_install_directory() {
        return blackduck_install_directory;
    }

    public Boolean isBlackduck_scan_full() {
        return blackduck_scan_full;
    }

    public Boolean isBlackduckIntelligentScan() {
        return blackduckIntelligentScan;
    }

    public String getBlackduck_scan_failure_severities() {
        return blackduck_scan_failure_severities;
    }

    public String getBlackduck_download_url() {
        return blackduck_download_url;
    }

    public Boolean isBlackduck_reports_sarif_create() {
        return blackduck_reports_sarif_create;
    }

    public String getBlackduck_reports_sarif_file_path() {
        return blackduck_reports_sarif_file_path;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues() {
        return blackduck_reports_sarif_groupSCAIssues;
    }

    public String getBlackduck_reports_sarif_severities() {
        return blackduck_reports_sarif_severities;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary() {
        return blackduck_reports_sarif_groupSCAIssues_temporary;
    }

    public Boolean isBlackduck_waitForScan() {
        return blackduck_waitForScan;
    }

    public Boolean isBlackduck_waitForScan_actualValue() {
        return blackduck_waitForScan_actualValue;
    }

    public Integer getBlackduck_search_depth() {
        return blackduck_search_depth;
    }

    public String getBlackduck_config_path() {
        return blackduck_config_path;
    }

    public String getBlackduck_args() {
        return blackduck_args;
    }

    public String getBlackduck_execution_path() {
        return blackduck_execution_path;
    }

    public String getCoverity_url() {
        return coverity_url;
    }

    public String getCoverity_user() {
        return coverity_user;
    }

    public String getCoverity_passphrase() {
        return coverity_passphrase;
    }

    public String getCoverity_project_name() {
        return coverity_project_name;
    }

    public String getCoverity_stream_name() {
        return coverity_stream_name;
    }

    public String getCoverity_policy_view() {
        return coverity_policy_view;
    }

    public String getCoverity_install_directory() {
        return coverity_install_directory;
    }

    public String getCoverity_version() {
        return coverity_version;
    }

    public Boolean isCoverity_local() {
        return coverity_local;
    }

    public Boolean isCoverity_waitForScan() {
        return coverity_waitForScan;
    }

    public Boolean isCoverity_waitForScan_actualValue() {
        return coverity_waitForScan_actualValue;
    }

    public String getCoverity_build_command() {
        return coverity_build_command;
    }

    public String getCoverity_clean_command() {
        return coverity_clean_command;
    }

    public String getCoverity_config_path() {
        return coverity_config_path;
    }

    public String getCoverity_args() {
        return coverity_args;
    }

    public String getCoverity_execution_path() {
        return coverity_execution_path;
    }

    public String getPolaris_server_url() {
        return polaris_server_url;
    }

    public String getPolaris_access_token() {
        return polaris_access_token;
    }

    public String getPolaris_application_name() {
        return polaris_application_name;
    }

    public String getPolaris_project_name() {
        return polaris_project_name;
    }

    public String getPolaris_assessment_types() {
        return polaris_assessment_types;
    }

    public String getPolaris_triage() {
        return polaris_triage;
    }

    public String getPolaris_branch_name() {
        return polaris_branch_name;
    }

    public String getPolaris_branch_parent_name() {
        return polaris_branch_parent_name;
    }

    public String getPolaris_prComment_severities() {
        return polaris_prComment_severities;
    }

    public Boolean isPolaris_reports_sarif_create() {
        return polaris_reports_sarif_create;
    }

    public String getPolaris_reports_sarif_file_path() {
        return polaris_reports_sarif_file_path;
    }

    public Boolean isPolaris_reports_sarif_groupSCAIssues() {
        return polaris_reports_sarif_groupSCAIssues;
    }

    public String getPolaris_reports_sarif_severities() {
        return polaris_reports_sarif_severities;
    }

    public String getPolaris_reports_sarif_issue_types() {
        return polaris_reports_sarif_issue_types;
    }

    public Boolean isPolaris_reports_sarif_groupSCAIssues_temporary() {
        return polaris_reports_sarif_groupSCAIssues_temporary;
    }

    public Boolean isPolaris_waitForScan() {
        return polaris_waitForScan;
    }

    public Boolean isPolaris_waitForScan_actualValue() {
        return polaris_waitForScan_actualValue;
    }

    public String getPolaris_assessment_mode() {
        return polaris_assessment_mode;
    }

    public String getPolaris_test_sca_type() {
        return polaris_test_sca_type;
    }

    public Integer getPolaris_sca_search_depth() {
        return polaris_sca_search_depth;
    }

    public String getPolaris_sca_config_path() {
        return polaris_sca_config_path;
    }

    public String getPolaris_sca_args() {
        return polaris_sca_args;
    }

    public String getPolaris_sast_build_command() {
        return polaris_sast_build_command;
    }

    public String getPolaris_sast_clean_command() {
        return polaris_sast_clean_command;
    }

    public String getPolaris_sast_config_path() {
        return polaris_sast_config_path;
    }

    public String getPolaris_sast_args() {
        return polaris_sast_args;
    }

    public String getProject_source_archive() {
        return project_source_archive;
    }

    public Boolean isProject_source_preserveSymLinks() {
        return project_source_preserveSymLinks;
    }

    public Boolean isProject_source_preserveSymLinks_actualValue() {
        return project_source_preserveSymLinks_actualValue;
    }

    public String getProject_source_excludes() {
        return project_source_excludes;
    }

    public String getProject_directory() {
        return project_directory;
    }

    public String getBlackduck_project_directory() {
        return blackduck_project_directory;
    }

    public String getCoverity_project_directory() {
        return coverity_project_directory;
    }

    public String getPolaris_project_directory() {
        return polaris_project_directory;
    }

    public String getSrm_project_directory() {
        return srm_project_directory;
    }

    public String getBitbucket_username() {
        return bitbucket_username;
    }

    public String getBitbucket_token() {
        return bitbucket_token;
    }

    public String getGithub_token() {
        return github_token;
    }

    public String getGitlab_token() {
        return gitlab_token;
    }

    public String getSynopsys_bridge_download_url() {
        return synopsys_bridge_download_url;
    }

    public String getSynopsys_bridge_download_version() {
        return synopsys_bridge_download_version;
    }

    public String getSynopsys_bridge_install_directory() {
        return synopsys_bridge_install_directory;
    }

    public Boolean isInclude_diagnostics() {
        return include_diagnostics;
    }

    public Boolean isNetwork_airgap() {
        return network_airgap;
    }

    public String getMark_build_status() {
        return mark_build_status;
    }

    public String getSrm_url() {
        return srm_url;
    }

    public String getSrm_apikey() {
        return srm_apikey;
    }

    public String getSrm_project_name() {
        return srm_project_name;
    }

    public String getSrm_project_id() {
        return srm_project_id;
    }

    public String getSrm_assessment_types() {
        return srm_assessment_types;
    }

    public String getSrm_branch_name() {
        return srm_branch_name;
    }

    public String getSrm_branch_parent() {
        return srm_branch_parent;
    }

    public Boolean isSrm_waitForScan() {
        return srm_waitForScan;
    }

    public Boolean isSrm_waitForScan_actualValue() {
        return srm_waitForScan_actualValue;
    }

    public Integer getSrm_sca_search_depth() {
        return srm_sca_search_depth;
    }

    public String getSrm_sca_config_path() {
        return srm_sca_config_path;
    }

    public String getSrm_sca_args() {
        return srm_sca_args;
    }

    public String getSrm_sast_build_command() {
        return srm_sast_build_command;
    }

    public String getSrm_sast_clean_command() {
        return srm_sast_clean_command;
    }

    public String getSrm_sast_config_path() {
        return srm_sast_config_path;
    }

    public String getSrm_sast_args() {
        return srm_sast_args;
    }

    @DataBoundSetter
    public void setProduct(String product) {
        this.product = product;
    }

    @DataBoundSetter
    public void setBlackduck_url(String blackduck_url) {
        this.blackduck_url = blackduck_url;
    }

    @DataBoundSetter
    public void setBlackduck_token(String blackduck_token) {
        this.blackduck_token = blackduck_token;
    }

    @DataBoundSetter
    public void setBlackduck_install_directory(String blackduck_install_directory) {
        this.blackduck_install_directory = blackduck_install_directory;
    }

    @DataBoundSetter
    public void setBlackduck_scan_full(Boolean blackduck_scan_full) {
        if (blackduck_scan_full) {
            this.blackduckIntelligentScan = true;
        }
        if (!blackduck_scan_full) {
            this.blackduckIntelligentScan = false;
        }
        this.blackduck_scan_full = blackduck_scan_full ? true : null;
    }

    @DataBoundSetter
    public void setBlackduck_scan_failure_severities(String blackduck_scan_failure_severities) {
        this.blackduck_scan_failure_severities = Util.fixEmptyAndTrim(blackduck_scan_failure_severities);
    }

    @DataBoundSetter
    public void setBlackduck_download_url(String blackduck_download_url) {
        this.blackduck_download_url = Util.fixEmptyAndTrim(blackduck_download_url);
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_create(Boolean blackduck_reports_sarif_create) {
        this.blackduck_reports_sarif_create = blackduck_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_file_path(String blackduck_reports_sarif_file_path) {
        this.blackduck_reports_sarif_file_path = Util.fixEmptyAndTrim(blackduck_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_groupSCAIssues(Boolean blackduck_reports_sarif_groupSCAIssues) {
        this.blackduck_reports_sarif_groupSCAIssues =
                this.blackduck_reports_sarif_groupSCAIssues_temporary = blackduck_reports_sarif_groupSCAIssues;
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_severities(String blackduck_reports_sarif_severities) {
        this.blackduck_reports_sarif_severities = Util.fixEmptyAndTrim(blackduck_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setBlackduck_waitForScan(Boolean blackduck_waitForScan) {
        this.blackduck_waitForScan = this.blackduck_waitForScan_actualValue = blackduck_waitForScan;
    }

    @DataBoundSetter
    public void setBlackduck_search_depth(Integer blackduck_search_depth) {
        this.blackduck_search_depth = blackduck_search_depth;
    }

    @DataBoundSetter
    public void setBlackduck_config_path(String blackduck_config_path) {
        this.blackduck_config_path = Util.fixEmptyAndTrim(blackduck_config_path);
    }

    @DataBoundSetter
    public void setBlackduck_args(String blackduck_args) {
        this.blackduck_args = Util.fixEmptyAndTrim(blackduck_args);
    }

    @DataBoundSetter
    public void setBlackduck_execution_path(String blackduck_execution_path) {
        this.blackduck_execution_path = Util.fixEmptyAndTrim(blackduck_execution_path);
    }

    @DataBoundSetter
    public void setCoverity_url(String coverity_url) {
        this.coverity_url = coverity_url;
    }

    @DataBoundSetter
    public void setCoverity_user(String coverity_user) {
        this.coverity_user = coverity_user;
    }

    @DataBoundSetter
    public void setCoverity_passphrase(String coverity_passphrase) {
        this.coverity_passphrase = coverity_passphrase;
    }

    @DataBoundSetter
    public void setCoverity_project_name(String coverity_project_name) {
        this.coverity_project_name = Util.fixEmptyAndTrim(coverity_project_name);
    }

    @DataBoundSetter
    public void setCoverity_stream_name(String coverity_stream_name) {
        this.coverity_stream_name = Util.fixEmptyAndTrim(coverity_stream_name);
    }

    @DataBoundSetter
    public void setCoverity_policy_view(String coverity_policy_view) {
        this.coverity_policy_view = Util.fixEmptyAndTrim(coverity_policy_view);
    }

    @DataBoundSetter
    public void setCoverity_install_directory(String coverity_install_directory) {
        this.coverity_install_directory = coverity_install_directory;
    }

    @DataBoundSetter
    public void setCoverity_version(String coverity_version) {
        this.coverity_version = Util.fixEmptyAndTrim(coverity_version);
    }

    @DataBoundSetter
    public void setCoverity_local(Boolean coverity_local) {
        this.coverity_local = coverity_local ? true : null;
    }

    @DataBoundSetter
    public void setCoverity_waitForScan(Boolean coverity_waitForScan) {
        this.coverity_waitForScan = this.coverity_waitForScan_actualValue = coverity_waitForScan;
    }

    @DataBoundSetter
    public void setCoverity_build_command(String coverity_build_command) {
        this.coverity_build_command = Util.fixEmptyAndTrim(coverity_build_command);
    }

    @DataBoundSetter
    public void setCoverity_clean_command(String coverity_clean_command) {
        this.coverity_clean_command = Util.fixEmptyAndTrim(coverity_clean_command);
    }

    @DataBoundSetter
    public void setCoverity_config_path(String coverity_config_path) {
        this.coverity_config_path = Util.fixEmptyAndTrim(coverity_config_path);
    }

    @DataBoundSetter
    public void setCoverity_args(String coverity_args) {
        this.coverity_args = Util.fixEmptyAndTrim(coverity_args);
    }

    @DataBoundSetter
    public void setCoverity_execution_path(String coverity_execution_path) {
        this.coverity_execution_path = Util.fixEmptyAndTrim(coverity_execution_path);
    }

    @DataBoundSetter
    public void setPolaris_server_url(String polaris_server_url) {
        this.polaris_server_url = polaris_server_url;
    }

    @DataBoundSetter
    public void setPolaris_access_token(String polaris_access_token) {
        this.polaris_access_token = polaris_access_token;
    }

    @DataBoundSetter
    public void setPolaris_application_name(String polaris_application_name) {
        this.polaris_application_name = Util.fixEmptyAndTrim(polaris_application_name);
    }

    @DataBoundSetter
    public void setPolaris_project_name(String polaris_project_name) {
        this.polaris_project_name = Util.fixEmptyAndTrim(polaris_project_name);
    }

    @DataBoundSetter
    public void setPolaris_assessment_types(String polaris_assessment_types) {
        this.polaris_assessment_types = Util.fixEmptyAndTrim(polaris_assessment_types);
    }

    @DataBoundSetter
    public void setPolaris_triage(String polaris_triage) {
        this.polaris_triage = Util.fixEmptyAndTrim(polaris_triage);
    }

    @DataBoundSetter
    public void setPolaris_branch_name(String polaris_branch_name) {
        this.polaris_branch_name = Util.fixEmptyAndTrim(polaris_branch_name);
    }

    @DataBoundSetter
    public void setPolaris_branch_parent_name(String polaris_branch_parent_name) {
        this.polaris_branch_parent_name = polaris_branch_parent_name;
    }

    @DataBoundSetter
    public void setPolaris_prComment_severities(String polaris_prComment_severities) {
        this.polaris_prComment_severities = polaris_prComment_severities;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_create(Boolean polaris_reports_sarif_create) {
        this.polaris_reports_sarif_create = polaris_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_file_path(String polaris_reports_sarif_file_path) {
        this.polaris_reports_sarif_file_path = Util.fixEmptyAndTrim(polaris_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_groupSCAIssues(Boolean polaris_reports_sarif_groupSCAIssues) {
        this.polaris_reports_sarif_groupSCAIssues =
                this.polaris_reports_sarif_groupSCAIssues_temporary = polaris_reports_sarif_groupSCAIssues;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_severities(String polaris_reports_sarif_severities) {
        this.polaris_reports_sarif_severities = Util.fixEmptyAndTrim(polaris_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_issue_types(String polaris_reports_sarif_issue_types) {
        this.polaris_reports_sarif_issue_types = Util.fixEmptyAndTrim(polaris_reports_sarif_issue_types);
    }

    @DataBoundSetter
    public void setPolaris_waitForScan(Boolean polaris_waitForScan) {
        this.polaris_waitForScan = this.polaris_waitForScan_actualValue = polaris_waitForScan;
    }

    @DataBoundSetter
    public void setBitbucket_username(String bitbucket_username) {
        this.bitbucket_username = bitbucket_username;
    }

    @DataBoundSetter
    public void setPolaris_assessment_mode(String polaris_assessment_mode) {
        this.polaris_assessment_mode = Util.fixEmptyAndTrim(polaris_assessment_mode);
    }

    @DataBoundSetter
    public void setPolaris_test_sca_type(String polaris_test_sca_type) {
        this.polaris_test_sca_type = Util.fixEmptyAndTrim(polaris_test_sca_type);
    }

    @DataBoundSetter
    public void setPolaris_sca_search_depth(Integer polaris_sca_search_depth) {
        this.polaris_sca_search_depth = polaris_sca_search_depth;
    }

    @DataBoundSetter
    public void setPolaris_sca_config_path(String polaris_sca_config_path) {
        this.polaris_sca_config_path = Util.fixEmptyAndTrim(polaris_sca_config_path);
    }

    @DataBoundSetter
    public void setPolaris_sca_args(String polaris_sca_args) {
        this.polaris_sca_args = Util.fixEmptyAndTrim(polaris_sca_args);
    }

    @DataBoundSetter
    public void setPolaris_sast_build_command(String polaris_sast_build_command) {
        this.polaris_sast_build_command = Util.fixEmptyAndTrim(polaris_sast_build_command);
    }

    @DataBoundSetter
    public void setPolaris_sast_clean_command(String polaris_sast_clean_command) {
        this.polaris_sast_clean_command = Util.fixEmptyAndTrim(polaris_sast_clean_command);
    }

    @DataBoundSetter
    public void setPolaris_sast_config_path(String polaris_sast_config_path) {
        this.polaris_sast_config_path = Util.fixEmptyAndTrim(polaris_sast_config_path);
    }

    @DataBoundSetter
    public void setPolaris_sast_args(String polaris_sast_args) {
        this.polaris_sast_args = Util.fixEmptyAndTrim(polaris_sast_args);
    }

    @DataBoundSetter
    public void setProject_source_archive(String project_source_archive) {
        this.project_source_archive = Util.fixEmptyAndTrim(project_source_archive);
    }

    @DataBoundSetter
    public void setProject_source_preserveSymLinks(Boolean project_source_preserveSymLinks) {
        this.project_source_preserveSymLinks =
                this.project_source_preserveSymLinks_actualValue = project_source_preserveSymLinks ? true : null;
    }

    @DataBoundSetter
    public void setProject_source_excludes(String project_source_excludes) {
        this.project_source_excludes = Util.fixEmptyAndTrim(project_source_excludes);
    }

    @DataBoundSetter
    public void setProject_directory(String project_directory) {
        this.project_directory = Util.fixEmptyAndTrim(project_directory);
    }

    @DataBoundSetter
    public void setCoverity_project_directory(String coverity_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.coverity_project_directory = this.project_directory = Util.fixEmptyAndTrim(coverity_project_directory);
    }

    @DataBoundSetter
    public void setBlackduck_project_directory(String blackduck_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCK.name().toLowerCase()))
            this.blackduck_project_directory =
                    this.project_directory = Util.fixEmptyAndTrim(blackduck_project_directory);
    }

    @DataBoundSetter
    public void setPolaris_project_directory(String polaris_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.polaris_project_directory = this.project_directory = Util.fixEmptyAndTrim(polaris_project_directory);
    }

    @DataBoundSetter
    public void setSrm_project_directory(String srm_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.srm_project_directory = this.project_directory = Util.fixEmptyAndTrim(srm_project_directory);
    }

    @DataBoundSetter
    public void setBitbucket_token(String bitbucket_token) {
        this.bitbucket_token = bitbucket_token;
    }

    @DataBoundSetter
    public void setGithub_token(String github_token) {
        this.github_token = github_token;
    }

    @DataBoundSetter
    public void setGitlab_token(String gitlab_token) {
        this.gitlab_token = gitlab_token;
    }

    @DataBoundSetter
    public void setSynopsys_bridge_download_url(String synopsys_bridge_download_url) {
        this.synopsys_bridge_download_url = synopsys_bridge_download_url;
    }

    @DataBoundSetter
    public void setSynopsys_bridge_download_version(String synopsys_bridge_download_version) {
        this.synopsys_bridge_download_version = synopsys_bridge_download_version;
    }

    @DataBoundSetter
    public void setSynopsys_bridge_install_directory(String synopsys_bridge_install_directory) {
        this.synopsys_bridge_install_directory = synopsys_bridge_install_directory;
    }

    @DataBoundSetter
    public void setInclude_diagnostics(Boolean include_diagnostics) {
        this.include_diagnostics = include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setNetwork_airgap(Boolean network_airgap) {
        this.network_airgap = network_airgap ? true : null;
    }

    @DataBoundSetter
    public void setMark_build_status(String mark_build_status) {
        this.mark_build_status = mark_build_status;
    }

    @DataBoundSetter
    public void setSrm_url(String srm_url) {
        this.srm_url = srm_url;
    }

    @DataBoundSetter
    public void setSrm_apikey(String srm_apikey) {
        this.srm_apikey = srm_apikey;
    }

    @DataBoundSetter
    public void setSrm_assessment_types(String srm_assessment_types) {
        this.srm_assessment_types = Util.fixEmptyAndTrim(srm_assessment_types);
    }

    @DataBoundSetter
    public void setSrm_project_name(String srm_project_name) {
        this.srm_project_name = Util.fixEmptyAndTrim(srm_project_name);
    }

    @DataBoundSetter
    public void setSrm_project_id(String srm_project_id) {
        this.srm_project_id = Util.fixEmptyAndTrim(srm_project_id);
    }

    @DataBoundSetter
    public void setSrm_branch_name(String srm_branch_name) {
        this.srm_branch_name = Util.fixEmptyAndTrim(srm_branch_name);
    }

    @DataBoundSetter
    public void setSrm_branch_parent(String srm_branch_parent) {
        this.srm_branch_parent = Util.fixEmptyAndTrim(srm_branch_parent);
    }

    @DataBoundSetter
    public void setSrm_waitForScan(Boolean srm_waitForScan) {
        this.srm_waitForScan = this.srm_waitForScan_actualValue = srm_waitForScan;
    }

    @DataBoundSetter
    public void setSrm_sca_search_depth(Integer srm_sca_search_depth) {
        this.srm_sca_search_depth = srm_sca_search_depth;
    }

    @DataBoundSetter
    public void setSrm_sca_config_path(String srm_sca_config_path) {
        this.srm_sca_config_path = srm_sca_config_path;
    }

    @DataBoundSetter
    public void setSrm_sca_args(String srm_sca_args) {
        this.srm_sca_args = srm_sca_args;
    }

    @DataBoundSetter
    public void setSrm_sast_build_command(String srm_sast_build_command) {
        this.srm_sast_build_command = srm_sast_build_command;
    }

    @DataBoundSetter
    public void setSrm_sast_clean_command(String srm_sast_clean_command) {
        this.srm_sast_clean_command = srm_sast_clean_command;
    }

    @DataBoundSetter
    public void setSrm_sast_config_path(String srm_sast_config_path) {
        this.srm_sast_config_path = srm_sast_config_path;
    }

    @DataBoundSetter
    public void setSrm_sast_args(String srm_sast_args) {
        this.srm_sast_args = srm_sast_args;
    }

    private Map<String, Object> getParametersMap(FilePath workspace, TaskListener listener)
            throws PluginExceptionHandler {
        return ScanParametersFactory.preparePipelineParametersMap(
                this, ScanParametersFactory.getGlobalConfigurationValues(workspace, listener), listener);
    }

    @Override
    public void perform(
            @NonNull Run<?, ?> run,
            @NonNull FilePath workspace,
            @NonNull EnvVars env,
            @NonNull Launcher launcher,
            @NonNull TaskListener listener) {
        int exitCode = 0;
        String undefinedErrorMessage = null;
        Exception unknownException = new Exception();
        LoggerWrapper logger = new LoggerWrapper(listener);

        logger.println(
                "**************************** START EXECUTION OF SYNOPSYS SECURITY SCAN ****************************");

        logger.warn(
                "This plugin has been deprecated and will not work after February 14, 2025. It is recommended that you migrate to our new Black Duck Security Scan (http://...). Instructions can be found at http://<community url>");

        try {
            exitCode = ScanParametersFactory.createPipelineCommand(run, listener, env, launcher, null, workspace)
                    .initializeScanner(getParametersMap(workspace, listener));
        } catch (Exception e) {
            if (e instanceof PluginExceptionHandler) {
                exitCode = ((PluginExceptionHandler) e).getCode();
            } else {
                exitCode = ErrorCode.UNDEFINED_PLUGIN_ERROR;
                undefinedErrorMessage = e.getMessage();
                unknownException = e;
            }
        } finally {
            String exitMessage = ExceptionMessages.getErrorMessage(exitCode, undefinedErrorMessage);
            if (exitMessage != null) {
                logger.info(exitMessage);
            }

            handleExitCode(run, logger, exitCode, exitMessage, unknownException);
        }
    }

    private void handleExitCode(Run<?, ?> run, LoggerWrapper logger, int exitCode, String exitMessage, Exception e) {
        if (exitCode != ErrorCode.BRIDGE_BUILD_BREAK && !Utility.isStringNullOrBlank(this.getMark_build_status())) {
            logger.info("Marking build status as " + this.getMark_build_status() + " is ignored since exit code is: "
                    + exitCode);
        }

        if (exitCode == ErrorCode.SCAN_SUCCESSFUL) {
            logger.info(
                    "**************************** END EXECUTION OF SYNOPSYS SECURITY SCAN ****************************");
        } else {
            Result result =
                    ScanParametersFactory.getBuildResultIfIssuesAreFound(exitCode, this.getMark_build_status(), logger);

            if (result != null) {
                logger.info("Marking build as " + result + " since issues are present");
                run.setResult(result);
            }

            logger.info(
                    "**************************** END EXECUTION OF SYNOPSYS SECURITY SCAN ****************************");

            if (result == null) {
                if (exitCode == ErrorCode.UNDEFINED_PLUGIN_ERROR) {
                    throw new RuntimeException(new ScannerException(exitMessage, e));
                } else {
                    throw new RuntimeException(new PluginExceptionHandler(exitMessage));
                }
            }
        }
    }

    @Extension
    public static class Descriptor extends BuildStepDescriptor<Builder> {

        @Override
        public String getDisplayName() {
            return ApplicationConstants.DISPLAY_NAME;
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return jobType.isAssignableFrom(FreeStyleProject.class);
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillProductItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(new ListBoxModel.Option(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "select"));

            for (SecurityProduct product : SecurityProduct.values()) {
                String label = product.getProductLabel();
                String value = product.name().toLowerCase();
                items.add(new ListBoxModel.Option(label, value));
            }
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillMark_build_statusItems() {
            ListBoxModel items = new ListBoxModel();

            items.add(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "");
            items.add(BuildStatus.FAILURE.name(), BuildStatus.FAILURE.name());
            items.add(BuildStatus.UNSTABLE.name(), BuildStatus.UNSTABLE.name());
            items.add(BuildStatus.SUCCESS.name(), BuildStatus.SUCCESS.name());

            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillPolaris_assessment_modeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(new ListBoxModel.Option(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, ""));
            items.add(new ListBoxModel.Option("CI", "CI"));
            items.add(new ListBoxModel.Option("SOURCE_UPLOAD", "SOURCE_UPLOAD"));
            return items;
        }
    }
}
