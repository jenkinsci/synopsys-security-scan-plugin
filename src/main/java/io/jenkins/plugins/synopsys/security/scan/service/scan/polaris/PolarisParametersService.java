package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Automation;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Parent;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Prcomment;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Test;
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
                        ApplicationConstants.POLARIS_PROJECT_NAME_KEY,
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

        validatePrcommentRelatedParamsForPolaris(polarisParameters, invalidParams);
                
        if (invalidParams.isEmpty()) {
            logger.info("Polaris parameters are validated successfully");
            return true;
        } else {
            logger.error("Polaris parameters are not valid");
            logger.error("Invalid Polaris parameters: " + invalidParams);
            return false;
        }
    }

    public void validatePrcommentRelatedParamsForPolaris(Map<String, Object> polarisParameters, List<String> invalidParams) {
        if (!isPrCommentEnabled(polarisParameters)) {
            return;
        }
        if (!isValidParentBranchNameKey(polarisParameters)) {
            invalidParams.add(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY);
        }
    }

    private boolean isPrCommentEnabled(Map<String, Object> polarisParameters) {
        return polarisParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)
                && Boolean.TRUE.equals(polarisParameters.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY));
    }

    private boolean isValidParentBranchNameKey(Map<String, Object> polarisParameters) {
        return polarisParameters.containsKey(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY)
                && polarisParameters.get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY) != null
                && !polarisParameters.get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY).toString().isEmpty();
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
                case ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY:
                    if (value.equals("true") || value.equals("false")) {
                        Prcomment prcomment = new Prcomment();
                        prcomment.setEnabled(Boolean.parseBoolean(value));
                        polaris.setPrcomment(prcomment);
                    }
                    break;
                case ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY:
                    if(!value.isEmpty()) {
                        Parent parent = new Parent();
                        polaris.getBranch().setParent(parent);
                        polaris.getBranch().getParent().setName(value);
                    }
                    break;
                case ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY:
                    if (!value.isEmpty()) {
                        List<String> prCommentSeverities = new ArrayList<>();
                        String[] prCommentSeveritiesInput = value.toUpperCase().split(",");

                        for (String input : prCommentSeveritiesInput) {
                            prCommentSeverities.add(input.trim());
                        }
                        polaris.getPrcomment().setSeverities(prCommentSeverities);
                    }
                    break;
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
                case ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY:
                    if (!value.isEmpty()) {
                        Test test = new Test();
                        test.getSca().setType(value);
                        polaris.setTest(test);
                    }
                    break;
                default:
                    break;
            }
        }
        return polaris;
    }
}
