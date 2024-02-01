package io.jenkins.plugins.synopsys.security.scan.bridge;

import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
import io.jenkins.plugins.synopsys.security.scan.global.HomeDirectoryTask;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import java.io.IOException;
import jenkins.model.Jenkins;

public class BridgeInstall {
    private final LoggerWrapper logger;
    private final FilePath workspace;

    public BridgeInstall(FilePath workspace, TaskListener listener) {
        this.workspace = workspace;
        this.logger = new LoggerWrapper(listener);
    }

    public void installSynopsysBridge(FilePath bridgeZipPath, FilePath bridgeInstallationPath) throws PluginExceptionHandler {
        try {
            if (bridgeZipPath != null && bridgeInstallationPath != null) {
                logger.info("Unzipping Synopsys Bridge zip file from: %s", bridgeZipPath.getRemote());
                bridgeZipPath.unzip(bridgeInstallationPath);
                logger.info("Synopsys Bridge installed successfully in: %", bridgeInstallationPath.getRemote());
            }
        } catch (IOException | InterruptedException e) {
            logger.error("An exception occurred while unzipping Synopsys Bridge zip file: " + e.getMessage());
            throw new PluginExceptionHandler(ErrorCode.SYNOPSYS_BRIDGE_UNZIPPING_FAILED);
        }

        // Deleting the bridge zip file after unzipping
        try {
            if (bridgeZipPath != null) {
                bridgeZipPath.delete();
            }
        } catch (IOException | InterruptedException e) {
            logger.warn("An exception occurred while deleting Synopsys Bridge zip file: " + e.getMessage());
        }
    }

    public String defaultBridgeInstallationPath(FilePath workspace, TaskListener listener) {

        logger.println("-------------------------------- Connection to node --------------------------------");

        Jenkins jenkins = Jenkins.getInstanceOrNull();
        String separator = Utility.getDirectorySeparator(workspace, listener);
        String defaultInstallationPath = null;

        if (jenkins != null && workspace.isRemote()) {
            logger.info("Jenkins job is running on agent node remotely");
        } else {
            logger.info("Jenkins job is running on master node");
        }

        try {
            defaultInstallationPath = workspace.act(new HomeDirectoryTask(separator));
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to fetch plugin's default installation path: %s", e.getMessage());
            Thread.currentThread().interrupt();
        }

        return defaultInstallationPath;
    }

    public void verifyAndCreateInstallationPath(String bridgeInstallationPath) {
        FilePath directory = new FilePath(workspace.getChannel(), bridgeInstallationPath);
        try {
            if (!directory.exists()) {
                directory.mkdirs();
                logger.info("Created bridge installation directory at: " + directory.getRemote());
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to create directory: " + directory.getRemote());
            Thread.currentThread().interrupt();
        }
    }
}
