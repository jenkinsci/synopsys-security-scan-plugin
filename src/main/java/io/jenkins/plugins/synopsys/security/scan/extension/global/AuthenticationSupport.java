package io.jenkins.plugins.synopsys.security.scan.extension.global;

import io.jenkins.plugins.synopsys.security.scan.global.ScanCredentialsHelper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.HttpClients;

public class AuthenticationSupport {
    private final String BLACKDUCK_AUTH_API = "api/tokens/authenticate";
    private final String POLARIS_PORTFOLIO_API = "api/portfolio/portfolios";
    private final String COVERITY_VIEWS_API = "api/v2/views";
    private final String AUTHORIZATION_HEADER = "Authorization";
    private int DEFAULT_CONNECTION_TIMEOUT = 20;
    private final ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

    public final HttpResponse attemptBlackDuckAuthentication(String blackDuckUrl, String blackDuckCredentialsId) {
        String blackDuckAuthApi = blackDuckUrl.endsWith("/") ?
            blackDuckUrl.concat(BLACKDUCK_AUTH_API) :
            blackDuckUrl.concat("/").concat(BLACKDUCK_AUTH_API);
        String blackDuckApiToken = scanCredentialsHelper.getApiTokenByCredentialsId(blackDuckCredentialsId).orElse(null);

        HttpPost httpPost = new HttpPost(blackDuckAuthApi);
        httpPost.setHeader(AUTHORIZATION_HEADER, "token " + blackDuckApiToken);

        return executeRequest(httpPost);
    }

    public final HttpResponse attemptPolarisAuthentication(String polarisServerUrl, String polarisCredentialsId) {
        String polarisAuthApi = polarisServerUrl.endsWith("/") ?
            polarisServerUrl.concat(POLARIS_PORTFOLIO_API) :
            polarisServerUrl.concat("/").concat(POLARIS_PORTFOLIO_API);
        String polarisAccessToken = scanCredentialsHelper.getApiTokenByCredentialsId(polarisCredentialsId).orElse(null);

        HttpGet httpGet = new HttpGet(polarisAuthApi);
        httpGet.setHeader("Api-token", polarisAccessToken);

        return executeRequest(httpGet);
    }

    public final HttpResponse attemptCoverityAuthentication(String coverityConnectUrl, String coverityCredentialsId) {
        String coverityAuthApi = coverityConnectUrl.endsWith("/") ?
            coverityConnectUrl.concat(COVERITY_VIEWS_API) :
            coverityConnectUrl.concat("/").concat(COVERITY_VIEWS_API);
        String username = scanCredentialsHelper.getUsernameByCredentialsId(coverityCredentialsId).orElse(null);
        String password = scanCredentialsHelper.getPasswordByCredentialsId(coverityCredentialsId).orElse(null);

        HttpGet httpGet = new HttpGet(coverityAuthApi);

        if (username != null && password != null) {
            String auth = username + ":" + password;
            byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
            httpGet.setHeader(AUTHORIZATION_HEADER, "Basic " + new String(encodedAuth));
        }

        return executeRequest(httpGet);
    }

    public HttpResponse executeRequest(HttpUriRequest httpUriRequest) {
        try {
            RequestConfig requestConfig = getRequestConfig(DEFAULT_CONNECTION_TIMEOUT);
            HttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build();
            return httpClient.execute(httpUriRequest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private RequestConfig getRequestConfig(int timeoutInSeconds) {
        return RequestConfig.custom()
            .setConnectTimeout(timeoutInSeconds * 1000)
            .setConnectionRequestTimeout(timeoutInSeconds * 1000)
            .setSocketTimeout(timeoutInSeconds * 1000)
            .build();
    }
}
