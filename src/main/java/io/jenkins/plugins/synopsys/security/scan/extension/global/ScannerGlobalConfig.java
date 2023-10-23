package io.jenkins.plugins.synopsys.security.scan.extension.global;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import java.io.Serializable;
import java.util.Collections;

import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

@Extension
public class ScannerGlobalConfig extends GlobalConfiguration implements Serializable {
    private static final long serialVersionUID = -3129542889827231427L;

    private String blackDuckUrl;

    private String blackDuckCredentialsId;
    private String blackDuckInstallationPath;
    private String coverityConnectUrl;
    private String coverityConnectUserName;
    private String coverityInstallationPath;
    private String synopsysBridgeDownloadUrlForMac;
    private String synopsysBridgeDownloadUrlForWindows;
    private String synopsysBridgeDownloadUrlForLinux;
    private String synopsysBridgeVersion;
    private String synopsysBridgeInstallationPath;

    private String bitbucketToken;

    private String polarisServerUrl;

    private String polarisCredentialsId;

    private String coverityCredentialsId;

    @DataBoundConstructor
    public ScannerGlobalConfig() {
        load();
    }

    @DataBoundSetter
    public void setBlackDuckUrl(String blackDuckUrl) {
        this.blackDuckUrl = blackDuckUrl;
        save();
    }

    @DataBoundSetter
    public void setBlackDuckInstallationPath(String blackDuckInstallationPath) {
        this.blackDuckInstallationPath = blackDuckInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setCoverityConnectUrl(String coverityConnectUrl) {
        this.coverityConnectUrl = coverityConnectUrl;
        save();
    }

    @DataBoundSetter
    public void setCoverityConnectUserName(String coverityConnectUserName) {
        this.coverityConnectUserName = coverityConnectUserName;
        save();
    }

    @DataBoundSetter
    public void setCoverityInstallationPath(String coverityInstallationPath) {
        this.coverityInstallationPath = coverityInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setBitbucketToken(String bitbucketToken) {
        this.bitbucketToken = bitbucketToken;
        save();
    }

    @DataBoundSetter
    public void setSynopsysBridgeDownloadUrlForMac(String synopsysBridgeDownloadUrlForMac) {
        this.synopsysBridgeDownloadUrlForMac = synopsysBridgeDownloadUrlForMac;
        save();
    }

    @DataBoundSetter
    public void setSynopsysBridgeDownloadUrlForWindows(String synopsysBridgeDownloadUrlForWindows) {
        this.synopsysBridgeDownloadUrlForWindows = synopsysBridgeDownloadUrlForWindows;
        save();
    }

    @DataBoundSetter
    public void setSynopsysBridgeDownloadUrlForLinux(String synopsysBridgeDownloadUrlForLinux) {
        this.synopsysBridgeDownloadUrlForLinux = synopsysBridgeDownloadUrlForLinux;
        save();
    }

    @DataBoundSetter
    public void setSynopsysBridgeVersion(String synopsysBridgeVersion) {
        this.synopsysBridgeVersion = synopsysBridgeVersion;
        save();
    }

    @DataBoundSetter
    public void setSynopsysBridgeInstallationPath(String synopsysBridgeInstallationPath) {
        this.synopsysBridgeInstallationPath = synopsysBridgeInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setPolarisServerUrl(String polarisServerUrl) {
        this.polarisServerUrl = polarisServerUrl;
        save();
    }

    @DataBoundSetter
    public void setBlackDuckCredentialsId(String blackDuckCredentialsId) {
        this.blackDuckCredentialsId = blackDuckCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setPolarisCredentialsId(String polarisCredentialsId) {
        this.polarisCredentialsId = polarisCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setCoverityCredentialsId(String coverityCredentialsId) {
        this.coverityCredentialsId = coverityCredentialsId;
        save();
    }

    public String getBlackDuckUrl() {
        return blackDuckUrl;
    }

    public String getBlackDuckInstallationPath() {
        return blackDuckInstallationPath;
    }

    public String getCoverityConnectUrl() {
        return coverityConnectUrl;
    }

    public String getCoverityInstallationPath() {
        return coverityInstallationPath;
    }

    public String getSynopsysBridgeDownloadUrlForMac() {
        return synopsysBridgeDownloadUrlForMac;
    }

    public String getSynopsysBridgeDownloadUrlForWindows() {
        return synopsysBridgeDownloadUrlForWindows;
    }

    public String getSynopsysBridgeDownloadUrlForLinux() {
        return synopsysBridgeDownloadUrlForLinux;
    }

    public String getSynopsysBridgeVersion() {
        return synopsysBridgeVersion;
    }

    public String getSynopsysBridgeInstallationPath() {
        return synopsysBridgeInstallationPath;
    }

    public String getPolarisServerUrl() {
        return polarisServerUrl;
    }

    public String getCoverityConnectUserName() {
        JenkinsWrapper jenkinsWrapper = JenkinsWrapper.initializeFromJenkinsJVM();
        jenkinsWrapper.getJenkins().get().checkPermission(Jenkins.ADMINISTER);

        ScanCredentialsHelper synopsysCredentialsHelper = jenkinsWrapper.getCredentialsHelper();
        return String.valueOf(synopsysCredentialsHelper.getIntegrationCredentialsById(coverityCredentialsId).getUsername());
    }

    public String getBlackDuckCredentialsId() {

        JenkinsWrapper jenkinsWrapper = JenkinsWrapper.initializeFromJenkinsJVM();
        jenkinsWrapper.getJenkins().get().checkPermission(Jenkins.ADMINISTER);

        ScanCredentialsHelper synopsysCredentialsHelper = jenkinsWrapper.getCredentialsHelper();
        return synopsysCredentialsHelper.getApiTokenByCredentialsId(blackDuckCredentialsId).orElse(null);
    }

    public String getPolarisCredentialsId() {

        JenkinsWrapper jenkinsWrapper = JenkinsWrapper.initializeFromJenkinsJVM();
        jenkinsWrapper.getJenkins().get().checkPermission(Jenkins.ADMINISTER);

        ScanCredentialsHelper synopsysCredentialsHelper = jenkinsWrapper.getCredentialsHelper();
        return synopsysCredentialsHelper.getApiTokenByCredentialsId(polarisCredentialsId).orElse(null);
    }

    public String getCoverityCredentialsId() {

        JenkinsWrapper jenkinsWrapper = JenkinsWrapper.initializeFromJenkinsJVM();
        jenkinsWrapper.getJenkins().get().checkPermission(Jenkins.ADMINISTER);

        ScanCredentialsHelper synopsysCredentialsHelper = jenkinsWrapper.getCredentialsHelper();
        return String.valueOf(synopsysCredentialsHelper.getUsernamePasswordCredentialsById(coverityCredentialsId).orElse(null));
    }

    public String getBitbucketToken() {

        JenkinsWrapper jenkinsWrapper = JenkinsWrapper.initializeFromJenkinsJVM();
        jenkinsWrapper.getJenkins().get().checkPermission(Jenkins.ADMINISTER);

        ScanCredentialsHelper synopsysCredentialsHelper = jenkinsWrapper.getCredentialsHelper();
        return synopsysCredentialsHelper.getApiTokenByCredentialsId(bitbucketToken).orElse(null);
    }

    public ListBoxModel doFillBlackDuckCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(ACL.SYSTEM, jenkins, BaseStandardCredentials.class, Collections.emptyList(), ScanCredentialsHelper.API_TOKEN_CREDENTIALS);
    }

    public ListBoxModel  doFillPolarisCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(ACL.SYSTEM, jenkins, BaseStandardCredentials.class, Collections.emptyList(), ScanCredentialsHelper.API_TOKEN_CREDENTIALS);
    }

    public ListBoxModel doFillCoverityCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(ACL.SYSTEM, jenkins, BaseStandardCredentials.class, Collections.emptyList(), ScanCredentialsHelper.USERNAME_PASSWORD_CREDENTIALS);
    }

    public ListBoxModel doFillBitbucketTokenItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(ACL.SYSTEM, jenkins, BaseStandardCredentials.class, Collections.emptyList(), ScanCredentialsHelper.API_TOKEN_CREDENTIALS);
    }
}
