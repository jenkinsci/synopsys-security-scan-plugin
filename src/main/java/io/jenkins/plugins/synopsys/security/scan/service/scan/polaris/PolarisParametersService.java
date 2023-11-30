package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PolarisParametersService {
    private final LoggerWrapper logger;

    public PolarisParametersService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public boolean isValidPolarisParameters(Map<String, Object> polarisParameters) {
        if (polarisParameters == null || polarisParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.POLARIS_SERVER_URL_KEY,
                        ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                        ApplicationConstants.POLARIS_APPLICATION_NAME_KEY,
                        ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY,
                        ApplicationConstants.POLARIS_BRANCH_NAME_KEY)
                .forEach(key -> {
                    boolean isKeyValid = polarisParameters.containsKey(key)
                            && polarisParameters.get(key) != null
                            && !polarisParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        if (invalidParams.isEmpty()) {
            logger.info("Polaris parameters are validated successfully");
            return true;
        } else {
            logger.error(LogMessages.POLARIS_PARAMETER_VALIDATION_FAILED);
            logger.error("Invalid Polaris parameters: " + invalidParams);
            return false;
        }
    }

    public Polaris preparePolarisObjectForBridge(Map<String, Object> polarisParameters) {
        Polaris polaris = new Polaris();

        for (Map.Entry<String, Object> entry : polarisParameters.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue().toString().trim();

            switch (key) {
                case ApplicationConstants.POLARIS_SERVER_URL_KEY:
                    polaris.setServerUrl(value);
                    break;
                case ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY:
                    polaris.setAccessToken(value);
                    break;
                case ApplicationConstants.POLARIS_APPLICATION_NAME_KEY:
                    polaris.getApplicationName().setName(value);
                    break;
                case ApplicationConstants.POLARIS_PROJECT_NAME_KEY:
                    polaris.getProjectName().setName(value);
                    break;
                case ApplicationConstants.POLARIS_TRIAGE_KEY:
                    polaris.setTriage(value);
                    break;
                case ApplicationConstants.POLARIS_BRANCH_NAME_KEY:
                    polaris.getBranch().setName(value);
                    break;
                    //                case ApplicationConstants.BRIDGE_POLARIS_BRANCH_PARENT_NAME_KEY:
                    //                    polaris.getBranch().getParent().setName(value);
                    //                    break;
                case ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY:
                    if (!value.isEmpty()) {
                        List<String> assessmentTypes = new ArrayList<>();
                        String[] assessmentTypesInput = value.toUpperCase().split(",");

                        for (String input : assessmentTypesInput) {
                            assessmentTypes.add(input.trim());
                        }
                        polaris.getAssessmentTypes().setTypes(assessmentTypes);
                    }
                    break;
                default:
                    break;
            }
        }
        return polaris;
    }
}
