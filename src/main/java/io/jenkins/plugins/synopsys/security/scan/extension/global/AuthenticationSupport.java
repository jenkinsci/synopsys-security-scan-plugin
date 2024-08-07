package io.jenkins.plugins.synopsys.security.scan.extension.global;

import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.util.Timeout;

public class AuthenticationSupport {
    private final ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

    public final HttpResponse attemptBlackDuckAuthentication(
            String blackDuckUrl, String blackDuckCredentialsId, int timeoutInSeconds) {
        String blackDuckAuthApi = blackDuckUrl.endsWith("/")
                ? blackDuckUrl.concat(ApplicationConstants.BLACKDUCK_AUTH_API)
                : blackDuckUrl.concat("/").concat(ApplicationConstants.BLACKDUCK_AUTH_API);
        String blackDuckApiToken = scanCredentialsHelper
                .getApiTokenByCredentialsId(blackDuckCredentialsId)
                .orElse(null);

        HttpPost httpPost = new HttpPost(blackDuckAuthApi);
        httpPost.setHeader(ApplicationConstants.AUTHORIZATION_HEADER_NAME, "token " + blackDuckApiToken);

        return executeRequest(httpPost, timeoutInSeconds);
    }

    public final HttpResponse attemptPolarisAuthentication(
            String polarisServerUrl, String polarisCredentialsId, int timeoutInSeconds) {
        String polarisAuthApi = polarisServerUrl.endsWith("/")
                ? polarisServerUrl.concat(ApplicationConstants.POLARIS_PORTFOLIO_API)
                : polarisServerUrl.concat("/").concat(ApplicationConstants.POLARIS_PORTFOLIO_API);
        String polarisAccessToken = scanCredentialsHelper
                .getApiTokenByCredentialsId(polarisCredentialsId)
                .orElse(null);

        HttpGet httpGet = new HttpGet(polarisAuthApi);
        httpGet.setHeader("Api-token", polarisAccessToken);

        return executeRequest(httpGet, timeoutInSeconds);
    }

    public final HttpResponse attemptCoverityAuthentication(
            String coverityConnectUrl, String coverityCredentialsId, int timeoutInSeconds) {
        String coverityAuthApi = coverityConnectUrl.endsWith("/")
                ? coverityConnectUrl.concat(ApplicationConstants.COVERITY_VIEWS_API)
                : coverityConnectUrl.concat("/").concat(ApplicationConstants.COVERITY_VIEWS_API);
        String username = scanCredentialsHelper
                .getUsernameByCredentialsId(coverityCredentialsId)
                .orElse(null);
        String password = scanCredentialsHelper
                .getPasswordByCredentialsId(coverityCredentialsId)
                .orElse(null);

        HttpGet httpGet = new HttpGet(coverityAuthApi);

        if (username != null && password != null) {
            String auth = username + ":" + password;
            String encodedAuth = Base64.encodeBase64String(auth.getBytes(StandardCharsets.UTF_8));
            httpGet.setHeader(ApplicationConstants.AUTHORIZATION_HEADER_NAME, "Basic " + encodedAuth);
        }

        return executeRequest(httpGet, timeoutInSeconds);
    }

    public final HttpResponse attemptSrmAuthentication(String srmUrl, String srmCredentialsId, int timeoutInSeconds) {
        String srmAuthApi = srmUrl.endsWith("/")
                ? srmUrl.concat(ApplicationConstants.SRM_SYSTEM_INFO_API)
                : srmUrl.concat("/").concat(ApplicationConstants.SRM_SYSTEM_INFO_API);
        String srmApiKey = scanCredentialsHelper
                .getApiTokenByCredentialsId(srmCredentialsId)
                .orElse(null);

        HttpGet httpGet = new HttpGet(srmAuthApi);
        httpGet.setHeader("API-Key", srmApiKey);

        return executeRequest(httpGet, timeoutInSeconds);
    }

    public HttpResponse executeRequest(HttpUriRequest httpUriRequest, int timeoutInSeconds) {
        try {
            RequestConfig requestConfig = getRequestConfig(timeoutInSeconds);
            HttpClient httpClient =
                    HttpClients.custom().setDefaultRequestConfig(requestConfig).build();
            return httpClient.execute(httpUriRequest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public RequestConfig getRequestConfig(int timeoutInSeconds) {
        return RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(timeoutInSeconds))
                .setResponseTimeout(Timeout.ofSeconds(timeoutInSeconds))
                .setConnectionRequestTimeout(Timeout.ofSeconds(timeoutInSeconds))
                .setConnectionKeepAlive(Timeout.ofSeconds(timeoutInSeconds))
                .build();
    }
}
