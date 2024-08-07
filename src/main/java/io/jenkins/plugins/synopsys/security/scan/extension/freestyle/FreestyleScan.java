package io.jenkins.plugins.synopsys.security.scan.extension.freestyle;

public interface FreestyleScan {
    public Integer getPolaris_sca_search_depth();

    public String getPolaris_sca_config_path();

    public String getPolaris_sca_args();

    public String getPolaris_sast_build_command();

    public String getPolaris_sast_clean_command();

    public String getPolaris_sast_config_path();

    public String getPolaris_sast_args();

    public Integer getSrm_sca_search_depth();

    public String getSrm_sca_config_path();

    public String getSrm_sca_args();

    public String getSrm_sast_build_command();

    public String getSrm_sast_clean_command();

    public String getSrm_sast_config_path();

    public String getSrm_sast_args();
}
