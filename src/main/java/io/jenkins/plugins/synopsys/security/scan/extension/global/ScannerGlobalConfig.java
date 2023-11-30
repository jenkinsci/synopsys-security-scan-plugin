package io.jenkins.plugins.synopsys.security.scan.extension.global;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.Locale;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.http.HttpResponse;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

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

    @POST
    public FormValidation doTestBlackDuckConnection(
        @QueryParameter("blackDuckUrl") String blackDuckUrl,
        @QueryParameter("blackDuckCredentialsId") String blackDuckCredentialsId
    ) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(
                "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.");
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(blackDuckUrl)) {
            return FormValidation.error("The Black Duck url must be specified");
        }
        if (Utility.isStringNullOrBlank(blackDuckCredentialsId)) {
            return FormValidation.error("The Black Duck credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptBlackDuckAuthentication(blackDuckUrl, blackDuckCredentialsId);

            if (response.getStatusLine().getStatusCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getStatusLine().getStatusCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error("Could not perform the authorization request: " + e.getCause().getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }

    private String getValidationMessage(int statusCode) {
        String validationMessage;
        try {
            String statusPhrase = EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, Locale.ENGLISH);
            validationMessage = String.format("ERROR: Connection attempt returned %s %s", statusCode, statusPhrase);
        } catch (IllegalArgumentException ignored) {
            validationMessage = "ERROR: Connection could not be established.";
        }
        return validationMessage;
    }

    @POST
    public FormValidation doTestPolarisConnection(
        @QueryParameter("polarisServerUrl") String polarisServerUrl,
        @QueryParameter("polarisCredentialsId") String polarisCredentialsId
    ) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(
                "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.");
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(polarisServerUrl)) {
            return FormValidation.error("The Polaris server url must be specified");
        }
        if (Utility.isStringNullOrBlank(polarisCredentialsId)) {
            return FormValidation.error("The Polaris credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptPolarisAuthentication(polarisServerUrl, polarisCredentialsId);

            if (response.getStatusLine().getStatusCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getStatusLine().getStatusCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error("Could not perform the authorization request: " + e.getCause().getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }

    @POST
    public FormValidation doTestCoverityConnection(
        @QueryParameter("coverityConnectUrl") String coverityConnectUrl,
        @QueryParameter("coverityCredentialsId") String coverityCredentialsId
    ) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(
                "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.");
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(coverityConnectUrl)) {
            return FormValidation.error("The Coverity connect url must be specified");
        }
        if (Utility.isStringNullOrBlank(coverityCredentialsId)) {
            return FormValidation.error("The Coverity credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptCoverityAuthentication(coverityConnectUrl, coverityCredentialsId);

            if (response.getStatusLine().getStatusCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getStatusLine().getStatusCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error("Could not perform the authorization request: " + e.getCause().getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }

}
