package io.jenkins.plugins.synopsys.security.scan.service.bridge;

import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridgeDownloadParametersService {
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final FilePath workspace;

    public BridgeDownloadParametersService(FilePath workspace, TaskListener listener) {
        this.workspace = workspace;
        this.listener = listener;
        this.logger = new LoggerWrapper(listener);
    }

    public boolean performBridgeDownloadParameterValidation(BridgeDownloadParameters bridgeDownloadParameters) {
        boolean validUrl = isValidUrl(bridgeDownloadParameters.getBridgeDownloadUrl());
        boolean validVersion = isValidVersion(bridgeDownloadParameters.getBridgeDownloadVersion());
        boolean validInstallationPath = isValidInstallationPath(bridgeDownloadParameters.getBridgeInstallationPath());

        if (validUrl && validVersion && validInstallationPath) {
            logger.info("Bridge download parameters are validated successfully");
            return true;
        } else {
            logger.error(LogMessages.INVALID_BRIDGE_DOWNLOAD_PARAMETERS);
            return false;
        }
    }

    public boolean isValidUrl(String url) {
        if (url.isEmpty()) {
            logger.warn(LogMessages.EMPTY_BRIDGE_DOWNLOAD_URL_PROVIDED);
            return false;
        }

        try {
            new URL(url);
            return true;
        } catch (Exception e) {
            logger.warn(LogMessages.INVALID_BRIDGE_DOWNLOAD_URL_PROVIDED, e.getMessage());
            return false;
        }
    }

    public boolean isValidVersion(String version) {
        Pattern pattern = Pattern.compile("\\d+\\.\\d+\\.\\d+");
        Matcher matcher = pattern.matcher(version);
        if (matcher.matches() || version.equals(ApplicationConstants.SYNOPSYS_BRIDGE_LATEST_VERSION)) {
            return true;
        } else {
            logger.warn(LogMessages.INVALID_BRIDGE_DOWNLOAD_VERSION_PROVIDED, version);
            return false;
        }
    }

    public boolean isValidInstallationPath(String installationPath) {
        try {
            FilePath path = new FilePath(workspace.getChannel(), installationPath);
            FilePath parentPath = path.getParent();

            if (parentPath != null && parentPath.exists() && parentPath.isDirectory()) {
                FilePath tempFile = parentPath.createTempFile("temp", null);
                boolean isWritable = tempFile.delete();

                if (isWritable) {
                    return true;
                } else {
                    logger.warn("The bridge installation parent path: %s is not writable", parentPath.toURI());
                    return false;
                }
            } else {
                if (parentPath == null || !parentPath.exists()) {
                    logger.warn("The bridge installation parent path: %s doesn't exist", path.toURI());
                } else if (!parentPath.isDirectory()) {
                    logger.warn("The bridge installation parent path: %s is not a directory", parentPath.toURI());
                }
                return false;
            }
        } catch (IOException | InterruptedException e) {
            logger.error("An exception occurred while validating the installation path: " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public BridgeDownloadParameters getBridgeDownloadParams(
            Map<String, Object> scanParameters, BridgeDownloadParameters bridgeDownloadParameters) {
        if (scanParameters.containsKey(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY)) {
            bridgeDownloadParameters.setBridgeInstallationPath(scanParameters
                    .get(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY)
                    .toString()
                    .trim());
        }

        boolean isNetworkAirgap = scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)
                && ((Boolean) scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY)).equals(true);

        if (scanParameters.containsKey(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL)) {
            bridgeDownloadParameters.setBridgeDownloadUrl(scanParameters
                    .get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL)
                    .toString()
                    .trim());
        } else if (scanParameters.containsKey(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION)
                && !isNetworkAirgap) {
            String desiredVersion = scanParameters
                    .get(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION)
                    .toString()
                    .trim();
            String bridgeDownloadUrl = String.join(
                    "/",
                    ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                    desiredVersion,
                    getSynopsysBridgeZipFileName(desiredVersion));

            bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
            bridgeDownloadParameters.setBridgeDownloadVersion(desiredVersion);
        } else {
            if (!isNetworkAirgap) {
                String bridgeDownloadUrl = String.join(
                        "/",
                        ApplicationConstants.BRIDGE_ARTIFACTORY_URL,
                        ApplicationConstants.SYNOPSYS_BRIDGE_LATEST_VERSION,
                        getSynopsysBridgeZipFileName());
                bridgeDownloadParameters.setBridgeDownloadUrl(bridgeDownloadUrl);
            }
        }
        return bridgeDownloadParameters;
    }

    public String getPlatform() {
        String os = Utility.getAgentOs(workspace, listener);
        if (os.contains("win")) {
            return ApplicationConstants.PLATFORM_WINDOWS;
        } else if (os.contains("mac")) {
            return ApplicationConstants.PLATFORM_MAC;
        } else {
            return ApplicationConstants.PLATFORM_LINUX;
        }
    }

    public String getSynopsysBridgeZipFileName() {
        return ApplicationConstants.BRIDGE_BINARY
                .concat("-")
                .concat(getPlatform())
                .concat(".zip");
    }

    public String getSynopsysBridgeZipFileName(String version) {
        return ApplicationConstants.BRIDGE_BINARY
                .concat("-")
                .concat(version)
                .concat("-")
                .concat(getPlatform())
                .concat(".zip");
    }
}
