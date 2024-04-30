package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Parent;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Prcomment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class PolarisParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public PolarisParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean isValidPolarisParameters(Map<String, Object> polarisParameters) {
        if (polarisParameters == null || polarisParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.POLARIS_SERVER_URL_KEY,
                        ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
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
            logger.error("Polaris parameters are not valid");
            logger.error("Invalid Polaris parameters: " + invalidParams);
            return false;
        }
    }

    public Polaris preparePolarisObjectForBridge(Map<String, Object> polarisParameters) {
        Polaris polaris = new Polaris();
        Prcomment prcomment = new Prcomment();

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_SERVER_URL_KEY)) {
            polaris.setServerUrl(polarisParameters
                    .get(ApplicationConstants.POLARIS_SERVER_URL_KEY)
                    .toString()
                    .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)) {
            polaris.setAccessToken(polarisParameters
                    .get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY)
                    .toString()
                    .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY)) {
            polaris.getApplicationName()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PROJECT_NAME_KEY)) {
            polaris.getProjectName()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_TRIAGE_KEY)) {
            polaris.setTriage(polarisParameters
                    .get(ApplicationConstants.POLARIS_TRIAGE_KEY)
                    .toString()
                    .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_BRANCH_NAME_KEY)) {
            polaris.getBranch()
                    .setName(polarisParameters
                            .get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)) {
            setPolarisPrCommentInputs(polarisParameters, prcomment, polaris);
        }

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)) {
            setAssessmentTypes(polarisParameters, polaris);
        }

        return polaris;
    }

    private void setAssessmentTypes(Map<String, Object> polarisParameters, Polaris polaris) {
        String assessmentTypesValue = polarisParameters
                .get(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)
                .toString()
                .trim();
        if (!assessmentTypesValue.isEmpty()) {
            List<String> assessmentTypes =
                    Arrays.asList(assessmentTypesValue.toUpperCase().split(","));
            polaris.getAssessmentTypes().setTypes(assessmentTypes);
        }
    }

    private void setPolarisPrCommentInputs(
            Map<String, Object> polarisParameters, Prcomment prcomment, Polaris polaris) {
        String isEnabled = polarisParameters
                .get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY)
                .toString()
                .trim();
        if (isEnabled.equals("true")) {
            boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
            if (isPullRequestEvent) {
                prcomment.setEnabled(true);

                if (polarisParameters.containsKey(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY)) {
                    String prCommentSeveritiesValue = polarisParameters
                            .get(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY)
                            .toString()
                            .trim();
                    if (!prCommentSeveritiesValue.isEmpty()) {
                        List<String> prCommentSeverities = Arrays.asList(
                                prCommentSeveritiesValue.toUpperCase().split(","));
                        prcomment.setSeverities(prCommentSeverities);
                    }
                }

                polaris.setPrcomment(prcomment);

                if (polarisParameters.containsKey(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY)) {
                    String parentName = polarisParameters
                            .get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY)
                            .toString()
                            .trim();
                    if (!parentName.isEmpty()) {
                        Parent parent = new Parent();
                        parent.setName(parentName);
                        polaris.getBranch().setParent(parent);
                    }
                }
            } else {
                logger.info(ApplicationConstants.POLARIS_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }
    }
}
