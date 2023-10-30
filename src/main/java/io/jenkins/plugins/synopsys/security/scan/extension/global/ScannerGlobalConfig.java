package io.jenkins.plugins.synopsys.security.scan.extension.global;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import java.io.Serializable;
import java.util.Collections;
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
    private String coverityCredentialsId;
    private String coverityInstallationPath;
    private String synopsysBridgeDownloadUrlForMac;
    private String synopsysBridgeDownloadUrlForWindows;
    private String synopsysBridgeDownloadUrlForLinux;
    private String synopsysBridgeVersion;
    private String synopsysBridgeInstallationPath;
    private String polarisServerUrl;
    private String polarisCredentialsId;
    private String bitbucketCredentialsId;

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
    public void setCoverityInstallationPath(String coverityInstallationPath) {
        this.coverityInstallationPath = coverityInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setBitbucketCredentialsId(String bitbucketCredentialsId) {
        this.bitbucketCredentialsId = bitbucketCredentialsId;
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

    public String getBlackDuckCredentialsId() {
        return blackDuckCredentialsId;
    }

    public String getCoverityCredentialsId() {
        return coverityCredentialsId;
    }

    public String getPolarisCredentialsId() {
        return polarisCredentialsId;
    }

    public String getBitbucketCredentialsId() {
        return bitbucketCredentialsId;
    }

    private ListBoxModel getOptionsWithApiTokenCredentials() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(
                        ACL.SYSTEM,
                        jenkins,
                        BaseStandardCredentials.class,
                        Collections.emptyList(),
                        ScanCredentialsHelper.API_TOKEN_CREDENTIALS);
    }

    public ListBoxModel doFillBlackDuckCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    public ListBoxModel doFillPolarisCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    public ListBoxModel doFillCoverityCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(
                        ACL.SYSTEM,
                        jenkins,
                        BaseStandardCredentials.class,
                        Collections.emptyList(),
                        ScanCredentialsHelper.USERNAME_PASSWORD_CREDENTIALS);
    }

    public ListBoxModel doFillBitbucketCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }
}
