package io.jenkins.plugins.synopsys.security.scan;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.bridge.BridgeDownloadManager;
import io.jenkins.plugins.synopsys.security.scan.bridge.BridgeDownloadParameters;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.service.bridge.BridgeDownloadParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.ScanParametersService;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class PluginParametersHandler {
    private final SecurityScanner scanner;
    private final FilePath workspace;
    private final TaskListener listener;
    private final EnvVars envVars;
    private final LoggerWrapper logger;

    public PluginParametersHandler(
            SecurityScanner scanner, FilePath workspace, EnvVars envVars, TaskListener listener) {
        this.scanner = scanner;
        this.workspace = workspace;
        this.listener = listener;
        this.envVars = envVars;
        this.logger = new LoggerWrapper(listener);
    }

    public int initializeScanner(Map<String, Object> scanParameters) throws PluginExceptionHandler {
        ScanParametersService scanParametersService = new ScanParametersService(listener, envVars);
        BridgeDownloadParameters bridgeDownloadParameters = new BridgeDownloadParameters(workspace, listener);
        BridgeDownloadParametersService bridgeDownloadParametersService =
                new BridgeDownloadParametersService(workspace, listener);
        BridgeDownloadParameters bridgeDownloadParams =
                bridgeDownloadParametersService.getBridgeDownloadParams(scanParameters, bridgeDownloadParameters);

        logMessagesForParameters(scanParameters, scanParametersService.getSynopsysSecurityProducts(scanParameters));

        scanParametersService.performScanParameterValidation(scanParameters, envVars);

        bridgeDownloadParametersService.performBridgeDownloadParameterValidation(bridgeDownloadParams);

        BridgeDownloadManager bridgeDownloadManager = new BridgeDownloadManager(workspace, listener, envVars);
        boolean isNetworkAirGap = checkNetworkAirgap(scanParameters);
        boolean isBridgeInstalled =
                bridgeDownloadManager.checkIfBridgeInstalled(bridgeDownloadParams.getBridgeInstallationPath());
        boolean isBridgeDownloadRequired = true;

        handleNetworkAirgap(isNetworkAirGap, bridgeDownloadParams, isBridgeInstalled);

        if (isBridgeInstalled) {
            isBridgeDownloadRequired = bridgeDownloadManager.isSynopsysBridgeDownloadRequired(bridgeDownloadParams);
        }

        handleBridgeDownload(isBridgeDownloadRequired, isNetworkAirGap, bridgeDownloadParams, bridgeDownloadManager);

        FilePath bridgeInstallationPath =
                new FilePath(workspace.getChannel(), bridgeDownloadParams.getBridgeInstallationPath());

        return scanner.runScanner(scanParameters, bridgeInstallationPath);
    }

    private boolean checkNetworkAirgap(Map<String, Object> scanParameters) {
        return scanParameters.containsKey(ApplicationConstants.NETWORK_AIRGAP_KEY)
                && scanParameters.get(ApplicationConstants.NETWORK_AIRGAP_KEY).equals(true);
    }

    private void handleNetworkAirgap(
            boolean isNetworkAirgap, BridgeDownloadParameters bridgeDownloadParams, boolean isBridgeInstalled)
            throws PluginExceptionHandler {
        if (isNetworkAirgap && !bridgeDownloadParams.getBridgeDownloadUrl().contains(".zip") && !isBridgeInstalled) {
            logger.error("Synopsys Bridge could not be found in " + bridgeDownloadParams.getBridgeInstallationPath());
            throw new PluginExceptionHandler(ErrorCode.SYNOPSYS_BRIDGE_NOT_FOUND_IN_PROVIDED_PATH);
        }

        if (isNetworkAirgap) {
            logger.info("Network Air Gap mode is enabled");
        }
    }

    private void handleBridgeDownload(
            boolean isBridgeDownloadRequired,
            boolean isNetworkAirgap,
            BridgeDownloadParameters bridgeDownloadParams,
            BridgeDownloadManager bridgeDownloadManager)
            throws PluginExceptionHandler {
        if (isBridgeDownloadRequired
                && bridgeDownloadParams.getBridgeDownloadUrl().contains(".zip")) {
            if (isNetworkAirgap) {
                logger.warn(
                        "Synopsys-Bridge will be downloaded from the provided custom URL. Make sure the network is reachable");
            }
            bridgeDownloadManager.initiateBridgeDownloadAndUnzip(bridgeDownloadParams);
        } else {
            logger.info("Bridge download is not required. Found installed in: "
                    + bridgeDownloadParams.getBridgeInstallationPath());
            logger.println(LogMessages.DASHES);
        }
    }

    public void logMessagesForParameters(Map<String, Object> scanParameters, Set<String> securityProducts) {
        logger.println("-------------------------- Parameter Validation Initiated --------------------------");

        logMessagesForProductParameters(scanParameters, securityProducts);

        logMessagesForBridgeParameters(scanParameters);

        if ((Objects.equals(scanParameters.get(ApplicationConstants.BLACKDUCK_REPORTS_SARIF_CREATE_KEY), true)
                        || Objects.equals(
                                scanParameters.get(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY), true))
                && envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY) != null) {
            logger.warn(
                    "SARIF report create/upload is ignored in case of PR/MR scan, it's only supported for non PR/MR scans");
        }
    }

    private void logMessagesForProductParameters(Map<String, Object> scanParameters, Set<String> securityProducts) {
        logger.info(LogMessages.LOG_DASH + ApplicationConstants.PRODUCT_KEY + " = " + securityProducts.toString());

        for (String product : securityProducts) {
            String securityProduct = product.toLowerCase();
            logger.info("Parameters for %s:", securityProduct);

            for (Map.Entry<String, Object> entry : scanParameters.entrySet()) {
                String key = entry.getKey();
                if (key.contains(securityProduct)) {
                    Object value = entry.getValue();
                    if (key.equals(ApplicationConstants.BLACKDUCK_TOKEN_KEY)
                            || key.equals(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)
                            || key.equals(ApplicationConstants.COVERITY_PASSPHRASE_KEY)) {
                        value = LogMessages.ASTERISKS;
                    }
                    logger.info(LogMessages.LOG_DASH + key + " = " + value.toString());
                }
            }

            logger.println(LogMessages.DASHES);
        }
    }

    private void logMessagesForBridgeParameters(Map<String, Object> scanParameters) {
        logger.info("Parameters for bridge:");

        for (Map.Entry<String, Object> entry : scanParameters.entrySet()) {
            String key = entry.getKey();
            if (key.equals(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_URL)
                    || key.equals(ApplicationConstants.SYNOPSYS_BRIDGE_DOWNLOAD_VERSION)
                    || key.equals(ApplicationConstants.SYNOPSYS_BRIDGE_INSTALL_DIRECTORY)
                    || key.equals(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY)
                    || key.equals(ApplicationConstants.NETWORK_AIRGAP_KEY)
                    || key.equals(ApplicationConstants.RETURN_STATUS_KEY)) {
                Object value = entry.getValue();
                logger.info(LogMessages.LOG_DASH + key + " = " + value.toString());
            }
        }
    }
}
