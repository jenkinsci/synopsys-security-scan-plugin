package io.jenkins.plugins.synopsys.security.scan.service.scan.coverity;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Install;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CoverityParametersService {
    private final LoggerWrapper logger;
    private final EnvVars envVars;

    public CoverityParametersService(TaskListener listener, EnvVars envVars) {
        this.logger = new LoggerWrapper(listener);
        this.envVars = envVars;
    }

    public boolean isValidCoverityParameters(Map<String, Object> coverityParameters) {
        if (coverityParameters == null || coverityParameters.isEmpty()) {
            return false;
        }

        List<String> invalidParams = getInvalidCoverityParamsForAllJobTypes(coverityParameters);

        if (invalidParams.isEmpty()) {
            logger.info("Coverity parameters are validated successfully");
            return true;
        } else {
            logger.error("Coverity parameters are not valid");
            logger.error("Invalid Coverity parameters: " + invalidParams);
            return false;
        }
    }

    private List<String> getInvalidCoverityParamsForAllJobTypes(Map<String, Object> coverityParameters) {
        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.COVERITY_URL_KEY,
                        ApplicationConstants.COVERITY_USER_KEY,
                        ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                .forEach(key -> {
                    boolean isKeyValid = coverityParameters.containsKey(key)
                            && coverityParameters.get(key) != null
                            && !coverityParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        invalidParams.addAll(getInvalidMandatoryParamsForFreeStyleAndPipeline(coverityParameters));

        return invalidParams;
    }

    private List<String> getInvalidMandatoryParamsForFreeStyleAndPipeline(Map<String, Object> coverityParameters) {
        List<String> invalidParamsForPipelineOrFreeStyle = new ArrayList<>();

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            Arrays.asList(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, ApplicationConstants.COVERITY_STREAM_NAME_KEY)
                    .forEach(key -> {
                        boolean isKeyValid = coverityParameters.containsKey(key)
                                && coverityParameters.get(key) != null
                                && !coverityParameters.get(key).toString().isEmpty();

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

    public Coverity prepareCoverityObjectForBridge(Map<String, Object> coverityParameters) {
        Coverity coverity = new Coverity();

        for (Map.Entry<String, Object> entry : coverityParameters.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue().toString().trim();

            switch (key) {
                case ApplicationConstants.COVERITY_URL_KEY:
                    coverity.getConnect().setUrl(value);
                    break;
                case ApplicationConstants.COVERITY_USER_KEY:
                    coverity.getConnect().getUser().setName(value);
                    break;
                case ApplicationConstants.COVERITY_PASSPHRASE_KEY:
                    coverity.getConnect().getUser().setPassword(value);
                    break;
                case ApplicationConstants.COVERITY_PROJECT_NAME_KEY:
                    coverity.getConnect().getProject().setName(value);
                    break;
                case ApplicationConstants.COVERITY_STREAM_NAME_KEY:
                    coverity.getConnect().getStream().setName(value);
                    break;
                case ApplicationConstants.COVERITY_POLICY_VIEW_KEY:
                    if(!value.isBlank()) {
                        coverity.getConnect().setPolicy(new Policy());
                        coverity.getConnect().getPolicy().setView(value);
                    }
                    break;
                case ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY:
                    if(!value.isBlank()) {
                        coverity.setInstall(new Install());
                        coverity.getInstall().setDirectory(value);
                    }
                    break;
                case ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY:
                    if (value.equals("true") || value.equals("false")) {
                        coverity.setAutomation(new Automation());
                        coverity.getAutomation().setPrComment(Boolean.parseBoolean(value));
                    }
                    break;
                case ApplicationConstants.COVERITY_VERSION_KEY:
                    coverity.setVersion(value);
                    break;
                case ApplicationConstants.COVERITY_LOCAL_KEY:
                    if (value.equals("true") || value.equals("false")) {
                        coverity.setLocal(Boolean.parseBoolean(value));
                    }
                    break;
                default:
                    break;
            }
        }
        return coverity;
    }
}
