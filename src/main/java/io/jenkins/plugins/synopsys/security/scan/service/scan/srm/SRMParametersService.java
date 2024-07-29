package io.jenkins.plugins.synopsys.security.scan.service.scan.srm;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.srm.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SRMParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public SRMParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean isValidSRMParameters(Map<String, Object> srmParameters) {
        if (srmParameters == null || srmParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = getInvalidSrmParamsForAllJobTypes(srmParameters);

        if (invalidParams.isEmpty()) {
            logger.info("SRM parameters are validated successfully");
            return true;
        } else {
            logger.error("SRM parameters are not valid");
            logger.error("Invalid SRM parameters: " + invalidParams);
            return false;
        }
    }

    private List<String> getInvalidSrmParamsForAllJobTypes(Map<String, Object> srmParameters) {
        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.SRM_URL_KEY,
                        ApplicationConstants.SRM_APIKEY_KEY,
                        ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)
                .forEach(key -> {
                    boolean isKeyValid = srmParameters.containsKey(key)
                            && srmParameters.get(key) != null
                            && !srmParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        invalidParams.addAll(getInvalidMandatoryParamsForFreeStyleAndPipeline(srmParameters));

        return invalidParams;
    }

    private List<String> getInvalidMandatoryParamsForFreeStyleAndPipeline(Map<String, Object> srmParameters) {
        List<String> invalidParamsForPipelineOrFreeStyle = new ArrayList<>();

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            Arrays.asList(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, ApplicationConstants.SRM_PROJECT_NAME_KEY)
                    .forEach(key -> {
                        boolean isKeyValid = srmParameters.containsKey(key)
                                && srmParameters.get(key) != null
                                && !srmParameters.get(key).toString().isEmpty();

                        if (!isKeyValid) {
                            invalidParamsForPipelineOrFreeStyle.add(key);
                        }
                    });
            if (!invalidParamsForPipelineOrFreeStyle.isEmpty()) {
                logger.error(invalidParamsForPipelineOrFreeStyle + " is mandatory parameter for "
                        + (jobType.equalsIgnoreCase(ApplicationConstants.FREESTYLE_JOB_TYPE_NAME)
                                ? "FreeStyle"
                                : "Pipeline")
                        + " job type");
            }
        }

        return invalidParamsForPipelineOrFreeStyle;
    }

    public SRM prepareSrmObjectForBridge(Map<String, Object> srmParameters) {
        SRM srm = new SRM();

        if (srmParameters.containsKey(ApplicationConstants.SRM_URL_KEY)) {
            srm.setUrl(srmParameters
                    .get(ApplicationConstants.SRM_URL_KEY)
                    .toString()
                    .trim());
        }

        if (srmParameters.containsKey(ApplicationConstants.SRM_APIKEY_KEY)) {
            srm.setApikey(srmParameters
                    .get(ApplicationConstants.SRM_APIKEY_KEY)
                    .toString()
                    .trim());
        }

        if (srmParameters.containsKey(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)) {
            setAssessmentTypes(srmParameters, srm);
        }

        if (srmParameters.containsKey(ApplicationConstants.SRM_PROJECT_NAME_KEY)) {
            srm.getProjectName()
                    .setName(srmParameters
                            .get(ApplicationConstants.SRM_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (srmParameters.containsKey(ApplicationConstants.SRM_BRANCH_NAME_KEY)) {
            srm.getBranch()
                    .setName(srmParameters
                            .get(ApplicationConstants.SRM_BRANCH_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (srmParameters.containsKey(ApplicationConstants.SRM_BRANCH_PARENT_KEY)) {
            srm.getBranch()
                    .setParent(srmParameters
                            .get(ApplicationConstants.SRM_BRANCH_PARENT_KEY)
                            .toString()
                            .trim());
        }

        return srm;
    }

    private void setAssessmentTypes(Map<String, Object> srmParameters, SRM srm) {
        String assessmentTypesValue = srmParameters
                .get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY)
                .toString()
                .trim();
        if (!assessmentTypesValue.isEmpty()) {
            List<String> assessmentTypes = Stream.of(
                            assessmentTypesValue.toUpperCase().split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
            srm.getAssessmentTypes().setTypes(assessmentTypes);
        }
    }
}
