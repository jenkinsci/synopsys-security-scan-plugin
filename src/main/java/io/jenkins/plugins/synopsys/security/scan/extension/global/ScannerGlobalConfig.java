package io.jenkins.plugins.synopsys.security.scan.extension.global;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.synopsys.integration.blackduck.configuration.BlackDuckServerConfig;
import com.synopsys.integration.blackduck.configuration.BlackDuckServerConfigBuilder;
import com.synopsys.integration.coverity.config.CoverityServerConfig;
import com.synopsys.integration.coverity.exception.CoverityIntegrationException;
import com.synopsys.integration.exception.IntegrationException;
import com.synopsys.integration.log.LogLevel;
import com.synopsys.integration.log.PrintStreamIntLogger;
import com.synopsys.integration.polaris.common.configuration.PolarisServerConfig;
import com.synopsys.integration.polaris.common.configuration.PolarisServerConfigBuilder;
import com.synopsys.integration.rest.client.ConnectionResult;
import com.synopsys.integration.rest.response.Response;
import hudson.Extension;
import hudson.Util;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Messages;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
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

        try {
            BlackDuckServerConfig blackDuckServerConfig = createBlackDuckServerConfigBuilder(
                blackDuckUrl,
                blackDuckCredentialsId
            ).build();
            Response response = blackDuckServerConfig.createBlackDuckHttpClient(new PrintStreamIntLogger(System.out, LogLevel.DEBUG)).attemptAuthentication();

            if (response.isStatusCodeError()) {
                int statusCode = response.getStatusCode();
                String validationMessage = determineValidationMessage(statusCode);

                String moreDetailsHtml = Optional.ofNullable(response.getContentString())
                    .map(Util::escape)
                    .map(msg -> String.format("<a href='#' class='showDetails'>%s</a><pre style='display:none'>%s</pre>", Messages.FormValidation_Error_Details(), msg))
                    .orElse(StringUtils.EMPTY);

                return FormValidation.errorWithMarkup(String.join(" ", validationMessage, moreDetailsHtml));
            }
        } catch (IllegalArgumentException | IntegrationException e) {
            return FormValidation.error(e.getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }

    private String determineValidationMessage(int statusCode) {
        String validationMessage;
        try {
            String statusPhrase = EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, Locale.ENGLISH);
            validationMessage = String.format("ERROR: Connection attempt returned %s %s", statusCode, statusPhrase);
        } catch (IllegalArgumentException ignored) {
            validationMessage = "ERROR: Connection could not be established.";
        }
        return validationMessage;
    }

    private BlackDuckServerConfigBuilder createBlackDuckServerConfigBuilder(String blackDuckUrl, String credentialsId) {
        ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

        return BlackDuckServerConfig.newApiTokenBuilder()
            .setUrl(blackDuckUrl)
            .setApiToken(scanCredentialsHelper.getApiTokenByCredentialsId(credentialsId).orElse(null))
            .setTimeoutInSeconds(120);
    }

    @POST
    public FormValidation doTestPolarisConnection(@QueryParameter("polarisServerUrl") String polarisServerUrl,
                                                  @QueryParameter("polarisCredentialsId") String polarisCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(
                "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.");
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        try {
            PolarisServerConfig polarisServerConfig = createPolarisServerConfigBuilder(polarisServerUrl, polarisCredentialsId).build();
            ConnectionResult connectionResult = polarisServerConfig.createPolarisHttpClient(new PrintStreamIntLogger(System.out, LogLevel.DEBUG)).attemptConnection();
            if (connectionResult.isFailure()) {
                int statusCode = connectionResult.getHttpStatusCode();
                String validationMessage = determineValidationMessage(statusCode);

                String moreDetailsHtml = connectionResult.getFailureMessage()
                    .map(Util::escape)
                    .map(msg -> String.format("<a href='#' class='showDetails'>%s</a><pre style='display:none'>%s</pre>", Messages.FormValidation_Error_Details(), msg))
                    .orElse(StringUtils.EMPTY);

                return FormValidation.errorWithMarkup(String.join(" ", validationMessage, moreDetailsHtml));
            }
        } catch (IllegalArgumentException e) {
            return FormValidation.error(e.getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }

    public PolarisServerConfigBuilder createPolarisServerConfigBuilder(String polarisUrl, String credentialsId) {
        ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

        return PolarisServerConfig.newBuilder()
            .setUrl(polarisUrl)
            .setAccessToken(scanCredentialsHelper.getApiTokenByCredentialsId(credentialsId).orElse(null))
            .setTimeoutInSeconds(120);
    }

    @POST
    public FormValidation doTestCoverityConnection(@QueryParameter("coverityConnectUrl") String coverityConnectUrl, @QueryParameter("coverityCredentialsId") String coverityCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(
                "Connection validation could not be completed: Validation couldn't retrieve the instance of Jenkins from the JVM. This may happen if Jenkins is still starting up or if this code is running on a different JVM than your Jenkins server.");
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        try {
            ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();
            CoverityServerConfig coverityServerConfig = CoverityServerConfig.newBuilder()
                .setUrl(coverityConnectUrl)
                .setCredentials(scanCredentialsHelper.getIntegrationCredentialsById(coverityCredentialsId))
                .build();

            coverityServerConfig.createWebServiceFactory(new PrintStreamIntLogger(System.out, LogLevel.DEBUG)).connect();
            ConnectionResult connectionResult = coverityServerConfig.attemptConnection(new PrintStreamIntLogger(System.out, LogLevel.DEBUG));
            if (connectionResult.isFailure()) {
                int statusCode = connectionResult.getHttpStatusCode();
                String validationMessage = determineValidationMessage(statusCode);

                String moreDetailsHtml = connectionResult.getFailureMessage()
                    .map(Util::escape)
                    .map(msg -> String.format("<a href='#' class='showDetails'>%s</a><pre style='display:none'>%s</pre>", Messages.FormValidation_Error_Details(), msg))
                    .orElse(StringUtils.EMPTY);

                return FormValidation.errorWithMarkup(String.join(" ", validationMessage, moreDetailsHtml));
            }
        } catch (IllegalArgumentException | MalformedURLException | CoverityIntegrationException e) {
            return FormValidation.error(e.getMessage());
        }

        return FormValidation.ok("Connection successful.");
    }
}
