package io.jenkins.plugins.synopsys.security.scan.bridge;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class BridgeDownload {
    private final LoggerWrapper logger;
    private final FilePath workspace;
    private final EnvVars envVars;

    public BridgeDownload(FilePath workspace, TaskListener listener, EnvVars envVars) {
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public FilePath downloadSynopsysBridge(String bridgeDownloadUrl, String bridgeInstallationPath)
            throws PluginExceptionHandler {
        FilePath bridgeZipFilePath = null;
        FilePath bridgeInstallationFilePath = new FilePath(workspace.getChannel(), bridgeInstallationPath);

        if (!checkIfBridgeUrlExists(bridgeDownloadUrl)) {
            logger.warn("Invalid Synopsys Bridge download URL: %s", bridgeDownloadUrl);
        }

        int retryCount = 1;
        boolean downloadSuccess = false;

        while (!downloadSuccess && retryCount <= ApplicationConstants.BRIDGE_DOWNLOAD_MAX_RETRIES) {
            try {
                logger.info("Downloading Synopsys Bridge from: " + bridgeDownloadUrl);
                bridgeZipFilePath = downloadBridge(bridgeDownloadUrl, bridgeInstallationFilePath);

                if (bridgeZipFilePath != null) {
                    downloadSuccess = true;
                }
            } catch (InterruptedException e) {
                logger.error("Interrupted while waiting to retry Synopsys Bridge download");
                Thread.currentThread().interrupt();
                throw new PluginExceptionHandler(ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_FAILED);
            } catch (Exception e) {
                handleDownloadException(bridgeDownloadUrl, retryCount);
                retryCount++;
            }
        }

        if (!downloadSuccess) {
            logger.error(
                    "Synopsys Bridge download failed after %s attempts",
                    ApplicationConstants.BRIDGE_DOWNLOAD_MAX_RETRIES);
        }

        if (bridgeZipFilePath == null) {
            throw new PluginExceptionHandler(ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_FAILED);
        }

        return bridgeZipFilePath;
    }

    private FilePath downloadBridge(String bridgeDownloadUrl, FilePath bridgeInstallationFilePath)
            throws InterruptedException, IOException {
        FilePath bridgeZipFilePath = bridgeInstallationFilePath.child(ApplicationConstants.BRIDGE_ZIP_FILE_FORMAT);
        HttpURLConnection connection = Utility.getHttpURLConnection(new URL(bridgeDownloadUrl), envVars, logger);

        if (connection != null) {
            bridgeZipFilePath.copyFrom(connection.getURL());
            logger.info("Synopsys Bridge successfully downloaded in: " + bridgeZipFilePath);
        }

        return bridgeZipFilePath;
    }

    private void handleDownloadException(String bridgeDownloadUrl, int retryCount) throws PluginExceptionHandler {
        int statusCode = getHttpStatusCode(bridgeDownloadUrl);

        if (terminateRetry(statusCode)) {
            logger.error(
                    "Synopsys Bridge download failed with status code: %s and plugin won't retry to download",
                    statusCode);
            throw new PluginExceptionHandler(ErrorCode.SYNOPSYS_BRIDGE_DOWNLOAD_FAILED_AND_WONT_RETRY);
        }

        try {
            Thread.sleep(ApplicationConstants.INTERVAL_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS);
        } catch (InterruptedException ie) {
            logger.warn("An exception occurred in between consecutive retry attempts: " + ie.getMessage());
            Thread.currentThread().interrupt();
        }
        logger.warn("Synopsys Bridge download failed and attempt#%s to download again.", retryCount);
    }

    public int getHttpStatusCode(String url) {
        int statusCode = -1;

        try {
            HttpURLConnection connection = Utility.getHttpURLConnection(new URL(url), envVars, logger);
            if (connection != null) {
                connection.setRequestMethod("HEAD");
                statusCode = connection.getResponseCode();
                connection.disconnect();
            }
        } catch (IOException e) {
            logger.error("An exception occurred while checking the http status code: " + e.getMessage());
        }

        return statusCode;
    }

    public boolean terminateRetry(int statusCode) {
        return statusCode == HttpURLConnection.HTTP_UNAUTHORIZED
                || statusCode == HttpURLConnection.HTTP_FORBIDDEN
                || statusCode == HttpURLConnection.HTTP_OK
                || statusCode == HttpURLConnection.HTTP_CREATED
                || statusCode == 416;
    }

    public boolean checkIfBridgeUrlExists(String bridgeDownloadUrl) {
        try {
            URL url = new URL(bridgeDownloadUrl);

            HttpURLConnection connection = Utility.getHttpURLConnection(url, envVars, logger);
            if (connection != null) {
                connection.setRequestMethod("HEAD");
                return (connection.getResponseCode() == HttpURLConnection.HTTP_OK);
            }
        } catch (Exception e) {
            logger.error("An exception occurred while checking bridge url exists or not: " + e.getMessage());
        }
        return false;
    }
}
