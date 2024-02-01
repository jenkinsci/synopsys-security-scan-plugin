package io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Download;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class BlackDuckParametersService {
    private final LoggerWrapper logger;

    public BlackDuckParametersService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public boolean isValidBlackDuckParameters(Map<String, Object> blackDuckParameters) {
        if (blackDuckParameters == null || blackDuckParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(ApplicationConstants.BLACKDUCK_URL_KEY, ApplicationConstants.BLACKDUCK_TOKEN_KEY)
                .forEach(key -> {
                    boolean isKeyValid = blackDuckParameters.containsKey(key)
                            && blackDuckParameters.get(key) != null
                            && !blackDuckParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        if (invalidParams.isEmpty()) {
            logger.info("BlackDuck parameters are validated successfully");
            return true;
        } else {
            logger.error("BlackDuck parameters are not valid");
            logger.error("Invalid BlackDuck parameters: " + invalidParams);
            return false;
        }
    }

    public BlackDuck prepareBlackDuckObjectForBridge(Map<String, Object> blackDuckParameters) {
        BlackDuck blackDuck = new BlackDuck();

        for (Map.Entry<String, Object> entry : blackDuckParameters.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue().toString().trim();

            switch (key) {
                case ApplicationConstants.BLACKDUCK_URL_KEY:
                    blackDuck.setUrl(value);
                    break;
                case ApplicationConstants.BLACKDUCK_TOKEN_KEY:
                    blackDuck.setToken(value);
                    break;
                case ApplicationConstants.BLACKDUCK_INSTALL_DIRECTORY_KEY:
                    setInstallDirectory(blackDuck, value);
                    break;
                case ApplicationConstants.BLACKDUCK_SCAN_FULL_KEY:
                    setScanFull(blackDuck, value);
                    break;
                case ApplicationConstants.BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY:
                    setScanFailureSeverities(blackDuck, value);
                    break;
                case ApplicationConstants.BLACKDUCK_AUTOMATION_FIXPR_KEY:
                    setAutomationFixpr(blackDuck, value);
                    break;
                case ApplicationConstants.BLACKDUCK_AUTOMATION_PRCOMMENT_KEY:
                    setAutomationPrComment(blackDuck, value);
                    break;
                case ApplicationConstants.BLACKDUCK_DOWNLOAD_URL_KEY:
                    setDownloadUrl(blackDuck, value);
                    break;
                default:
                    break;
            }
        }

        return blackDuck;
    }

    private void setInstallDirectory(BlackDuck blackDuck, String value) {
        blackDuck.getInstall().setDirectory(value);
    }

    private void setScanFull(BlackDuck blackDuck, String value) {
        if (isBoolean(value)) {
            blackDuck.getScan().setFull(Boolean.parseBoolean(value));
        }
    }

    private void setScanFailureSeverities(BlackDuck blackDuck, String value) {
        if (!value.isEmpty()) {
            List<String> failureSeverities = new ArrayList<>();
            String[] failureSeveritiesInput = value.toUpperCase().split(",");

            for (String input : failureSeveritiesInput) {
                failureSeverities.add(input.trim());
            }
            blackDuck.getScan().getFailure().setSeverities(failureSeverities);
        }
    }

    private void setAutomationFixpr(BlackDuck blackDuck, String value) {
        if (isBoolean(value)) {
            blackDuck.getAutomation().setFixpr(Boolean.parseBoolean(value));
        }
    }

    private void setAutomationPrComment(BlackDuck blackDuck, String value) {
        if (isBoolean(value)) {
            blackDuck.getAutomation().setPrComment(Boolean.parseBoolean(value));
        }
    }

    private void setDownloadUrl(BlackDuck blackDuck, String value) {
        Download download = new Download();
        download.setUrl(value);
        blackDuck.setDownload(download);
    }

    private boolean isBoolean(String value) {
        return value.equals("true") || value.equals("false");
    }
}
