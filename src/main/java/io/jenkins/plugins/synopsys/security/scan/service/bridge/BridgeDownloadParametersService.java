package io.jenkins.plugins.synopsys.security.scan.service.bridge;

import com.fasterxml.jackson.core.Version;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.IOException;
import java.net.MalformedURLException;
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

    public boolean performBridgeDownloadParameterValidation(BridgeDownloadParameters bridgeDownloadParameters)
            throws PluginExceptionHandler {
        boolean validUrl = isValidUrl(bridgeDownloadParameters.getBridgeDownloadUrl());
        boolean validVersion = isValidVersion(bridgeDownloadParameters.getBridgeDownloadVersion());
        boolean validInstallationPath = isValidInstallationPath(bridgeDownloadParameters.getBridgeInstallationPath());

        if (validUrl && validVersion && validInstallationPath) {
            logger.info("Bridge download parameters are validated successfully");
            return true;
        } else {
            logger.error("Bridge download parameters are not valid");
            throw new PluginExceptionHandler(ErrorCode.INVALID_BRIDGE_DOWNLOAD_PARAMETERS);
        }
    }

    public boolean isValidUrl(String url) {
        if (url.isEmpty()) {
            logger.warn("The provided Bridge download URL is empty");
            return false;
        }

        try {
            new URL(url);
            return true;
        } catch (MalformedURLException me) {
            logger.warn("The provided Bridge download URL is not valid: %s", me.getMessage());
            return false;
        }
    }

    public boolean isValidVersion(String version) {
        Pattern pattern = Pattern.compile("\\d+\\.\\d+\\.\\d+");
        Matcher matcher = pattern.matcher(version);
        if (matcher.matches() || version.equals(ApplicationConstants.SYNOPSYS_BRIDGE_LATEST_VERSION)) {
            return true;
        } else {
            logger.warn("The provided Bridge download version is not valid: %s", version);
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
                && scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY).equals(true);

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

    public String getPlatform(String version) {
        String os = Utility.getAgentOs(workspace, listener);
        if (os.contains("win")) {
            return ApplicationConstants.PLATFORM_WINDOWS;
        } else if (os.contains("mac")) {
            String arch = Utility.getAgentOsArch(workspace, listener);
            if (version != null && !isVersionCompatibleForMacARM(version)) {
                return ApplicationConstants.PLATFORM_MACOSX;
            } else {
                if (arch.startsWith("arm") || arch.startsWith("aarch")) {
                    return ApplicationConstants.PLATFORM_MAC_ARM;
                } else {
                    return ApplicationConstants.PLATFORM_MACOSX;
                }
            }
        } else {
            return ApplicationConstants.PLATFORM_LINUX;
        }
    }

    public String getSynopsysBridgeZipFileName() {
        return ApplicationConstants.BRIDGE_BINARY
                .concat("-")
                .concat(getPlatform(null))
                .concat(".zip");
    }

    public String getSynopsysBridgeZipFileName(String version) {
        return ApplicationConstants.BRIDGE_BINARY
                .concat("-")
                .concat(version)
                .concat("-")
                .concat(getPlatform(version))
                .concat(".zip");
    }

    public boolean isVersionCompatibleForMacARM(String version) {
        String[] inputVersionSplits = version.split("\\.");
        String[] minCompatibleArmVersionSplits = ApplicationConstants.MAC_ARM_COMPATIBLE_BRIDGE_VERSION.split("\\.");
        if (inputVersionSplits.length != 3 && minCompatibleArmVersionSplits.length != 3) {
            return false;
        }
        Version inputVersion = new Version(
                Integer.parseInt(inputVersionSplits[0]),
                Integer.parseInt(inputVersionSplits[1]),
                Integer.parseInt(inputVersionSplits[2]),
                null,
                null,
                null);
        Version minCompatibleArmVersion = new Version(
                Integer.parseInt(minCompatibleArmVersionSplits[0]),
                Integer.parseInt(minCompatibleArmVersionSplits[1]),
                Integer.parseInt(minCompatibleArmVersionSplits[2]),
                null,
                null,
                null);

        return inputVersion.compareTo(minCompatibleArmVersion) >= 0;
    }
}
