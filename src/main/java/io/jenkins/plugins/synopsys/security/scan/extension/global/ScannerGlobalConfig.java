package io.jenkins.plugins.synopsys.security.scan.extension.global;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.impl.EnglishReasonPhraseCatalog;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

@Extension
public class ScannerGlobalConfig extends GlobalConfiguration implements Serializable {
    private static final long serialVersionUID = -3129542889827231427L;
    private final int CONNECTION_TIMEOUT_IN_SECONDS = 120;
    private String AUTHORIZATION_FAILURE = "Could not perform the authorization request: ";
    private String CONNECTION_SUCCESSFUL = "Connection successful.";

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
    private String githubCredentialsId;
    private String gitlabCredentialsId;

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
    public void setGithubCredentialsId(String githubCredentialsId) {
        this.githubCredentialsId = githubCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setGitlabCredentialsId(String gitlabCredentialsId) {
        this.gitlabCredentialsId = gitlabCredentialsId;
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

    public String getGithubCredentialsId() {
        return githubCredentialsId;
    }

    public String getGitlabCredentialsId() {
        return gitlabCredentialsId;
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

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillBitbucketCredentialsIdItems() {
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
                        CredentialsMatchers.anyOf(
                                ScanCredentialsHelper.USERNAME_PASSWORD_CREDENTIALS,
                                ScanCredentialsHelper.API_TOKEN_CREDENTIALS));
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillGithubCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillGitlabCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @POST
    public FormValidation doTestBlackDuckConnection(
            @QueryParameter("blackDuckUrl") String blackDuckUrl,
            @QueryParameter("blackDuckCredentialsId") String blackDuckCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
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
            HttpResponse response = authenticationSupport.attemptBlackDuckAuthentication(
                    blackDuckUrl, blackDuckCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
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
            @QueryParameter("polarisCredentialsId") String polarisCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
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
            HttpResponse response = authenticationSupport.attemptPolarisAuthentication(
                    polarisServerUrl, polarisCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    @POST
    public FormValidation doTestCoverityConnection(
            @QueryParameter("coverityConnectUrl") String coverityConnectUrl,
            @QueryParameter("coverityCredentialsId") String coverityCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
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
            HttpResponse response = authenticationSupport.attemptCoverityAuthentication(
                    coverityConnectUrl, coverityCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    private String getFormattedExceptionMessage(String message) {
        Pattern pattern = Pattern.compile("failed: (.*)");
        Matcher matcher = pattern.matcher(message);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return message;
        }
    }
}
