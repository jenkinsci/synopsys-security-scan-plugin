/*
 * synopsys-security-scan-plugin
 *
 * Copyright (c) 2023 Synopsys, Inc.
 *
 * Use subject to the terms and conditions of the Synopsys End User Software License and Maintenance Agreement. All rights reserved worldwide.
 */
package com.synopsys.integration.jenkins.scan.service.scan.coverity;

import com.synopsys.integration.jenkins.scan.global.ApplicationConstants;
import com.synopsys.integration.jenkins.scan.global.LogMessages;
import com.synopsys.integration.jenkins.scan.global.LoggerWrapper;
import com.synopsys.integration.jenkins.scan.global.enums.ScanType;
import com.synopsys.integration.jenkins.scan.input.coverity.Coverity;
import com.synopsys.integration.jenkins.scan.strategy.ScanStrategy;
import hudson.model.TaskListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CoverityParametersService implements ScanStrategy {
    private final LoggerWrapper logger;

    public CoverityParametersService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    @Override
    public ScanType getScanType() {
        return ScanType.COVERITY;
    }

    @Override
    public boolean isValidScanParameters(Map<String, Object> coverityParameters) {
        if (coverityParameters == null || coverityParameters.isEmpty()) {
            return false;
        }

        logger.info("parameters for coverity:");

        for (Map.Entry<String, Object> entry : coverityParameters.entrySet()) {
            String key = entry.getKey();
            if(key.startsWith("bridge_blackduck") || key.startsWith("bridge_polaris")) continue;
            if(key.equals(ApplicationConstants.COVERITY_CONNECT_USER_PASSWORD_KEY)) {
                entry.setValue(LogMessages.ASTERISKS);
            }
            Object value = entry.getValue();
            logger.info(" --- " + key + " = " + value);
        }
        
        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(ApplicationConstants.BRIDGE_COVERITY_CONNECT_URL_KEY,
            ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_NAME_KEY,
            ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_PASSWORD_KEY)
            .forEach(key -> {
                boolean isKeyValid = coverityParameters.containsKey(key)
                    && coverityParameters.get(key) != null
                    && !coverityParameters.get(key).toString().isEmpty();

                if (!isKeyValid) {
                    invalidParams.add(key);
                }
            });

        if (invalidParams.isEmpty()) {
            logger.info("Coverity parameters are validated successfully");
            return true;
        } else {
            logger.error(LogMessages.COVERITY_PARAMETER_VALIDATION_FAILED);
            logger.error("Invalid Coverity parameters: " + invalidParams);
            return false;
        }
    }

    @Override
    public Coverity prepareScanInputForBridge(Map<String, Object> coverityParameters) {
        Coverity coverity = new Coverity();

        for (Map.Entry<String, Object> entry : coverityParameters.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue().toString().trim();

            switch (key) {
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_URL_KEY:
                    coverity.getConnect().setUrl(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_NAME_KEY:
                    coverity.getConnect().getUser().setName(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_USER_PASSWORD_KEY:
                    coverity.getConnect().getUser().setPassword(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_PROJECT_NAME_KEY:
                    coverity.getConnect().getProject().setName(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_STREAM_NAME_KEY:
                    coverity.getConnect().getStream().setName(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_CONNECT_POLICY_VIEW_KEY:
                    coverity.getConnect().getPolicy().setView(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_INSTALL_DIRECTORY_KEY:
                    coverity.getInstall().setDirectory(value);
                    break;
                case ApplicationConstants.BRIDGE_COVERITY_AUTOMATION_PRCOMMENT_KEY:
                    if (value.equals("true") || value.equals("false")) {
                        coverity.getAutomation().setPrComment(Boolean.parseBoolean(value));
                    }
                    break;
                default:
                    break;
            }
        }
        return coverity;
    }
}
