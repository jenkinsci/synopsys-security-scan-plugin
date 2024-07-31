package io.jenkins.plugins.synopsys.security.scan.service.scan.coverity;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Install;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.*;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
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

    public boolean hasAllMandatoryCoverityParams(Map<String, Object> coverityParameters) {
        if (coverityParameters == null || coverityParameters.isEmpty()) {
            return false;
        }

        List<String> missingMandatoryParams = getCoverityMissingMandatoryParams(coverityParameters);

        if (missingMandatoryParams.isEmpty()) {
            logger.info("Coverity parameters are validated successfully");
            return true;
        } else {
            String message;
            if (missingMandatoryParams.size() == 1) {
                message = "Required parameter Coverity is missing: " + missingMandatoryParams.get(0);
            } else {
                message = "Required parameters Coverity are missing: " + String.join(", ", missingMandatoryParams);
            }

            logger.error(message);
            return false;
        }
    }

    private List<String> getCoverityMissingMandatoryParams(Map<String, Object> coverityParameters) {
        List<String> missingMandatoryParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.COVERITY_URL_KEY,
                        ApplicationConstants.COVERITY_USER_KEY,
                        ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                .forEach(key -> {
                    boolean isKeyValid = coverityParameters.containsKey(key)
                            && coverityParameters.get(key) != null
                            && !coverityParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingMandatoryParams.add(key);
                    }
                });

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            missingMandatoryParams.addAll(getFreeStyleAndPipelineCoverityMissingMandatoryParams(coverityParameters));
        }

        if (!missingMandatoryParams.isEmpty()) {
            String jobTypeName;
            if (jobType.equalsIgnoreCase(ApplicationConstants.FREESTYLE_JOB_TYPE_NAME)) {
                jobTypeName = "FreeStyle";
            } else if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
                jobTypeName = "Multibranch Pipeline";
            } else {
                jobTypeName = "Pipeline";
            }

            logger.error(missingMandatoryParams + " is mandatory parameter for " + jobTypeName + " job type");
        }

        return missingMandatoryParams;
    }

    private List<String> getFreeStyleAndPipelineCoverityMissingMandatoryParams(Map<String, Object> coverityParameters) {
        List<String> missingParamsForFreeStyleAndPipeline = new ArrayList<>();

        Arrays.asList(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, ApplicationConstants.COVERITY_STREAM_NAME_KEY)
                .forEach(key -> {
                    boolean isKeyValid = coverityParameters.containsKey(key)
                            && coverityParameters.get(key) != null
                            && !coverityParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        missingParamsForFreeStyleAndPipeline.add(key);
                    }
                });

        return missingParamsForFreeStyleAndPipeline;
    }

    public Coverity prepareCoverityObjectForBridge(Map<String, Object> coverityParameters) {
        Coverity coverity = new Coverity();
        coverity.setConnect(new Connect());

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_URL_KEY)) {
            coverity.getConnect()
                    .setUrl(coverityParameters
                            .get(ApplicationConstants.COVERITY_URL_KEY)
                            .toString()
                            .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_USER_KEY)) {
            coverity.getConnect()
                    .getUser()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_USER_KEY)
                            .toString()
                            .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_PASSPHRASE_KEY)) {
            coverity.getConnect()
                    .getUser()
                    .setPassword(coverityParameters
                            .get(ApplicationConstants.COVERITY_PASSPHRASE_KEY)
                            .toString()
                            .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_PROJECT_NAME_KEY)) {
            coverity.getConnect()
                    .getProject()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_PROJECT_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_STREAM_NAME_KEY)) {
            coverity.getConnect()
                    .getStream()
                    .setName(coverityParameters
                            .get(ApplicationConstants.COVERITY_STREAM_NAME_KEY)
                            .toString()
                            .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_POLICY_VIEW_KEY)) {
            setCoverityPolicyView(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY)) {
            setCoverityInstallDirectory(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY)) {
            setCoverityPrComment(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_VERSION_KEY)) {
            coverity.setVersion(coverityParameters
                    .get(ApplicationConstants.COVERITY_VERSION_KEY)
                    .toString()
                    .trim());
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_LOCAL_KEY)) {
            setCoverityLocal(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY)) {
            setBuildCommand(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY)) {
            setCleanCommand(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_CONFIG_PATH_KEY)) {
            setConfigCommand(coverityParameters, coverity);
        }

        if (coverityParameters.containsKey(ApplicationConstants.COVERITY_ARGS_KEY)) {
            coverity.setArgs(coverityParameters
                    .get(ApplicationConstants.COVERITY_ARGS_KEY)
                    .toString()
                    .trim());
        }

        return coverity;
    }

    private void setCoverityLocal(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_LOCAL_KEY)
                .toString()
                .trim();
        if (value.equals("true") || value.equals("false")) {
            coverity.setLocal(Boolean.parseBoolean(value));
        }
    }

    private void setCoverityPrComment(Map<String, Object> coverityParameters, Coverity coverity) {
        String isEnabled = coverityParameters
                .get(ApplicationConstants.COVERITY_AUTOMATION_PRCOMMENT_KEY)
                .toString()
                .trim();
        if (isEnabled.equals("true")) {
            boolean isPullRequestEvent = Utility.isPullRequestEvent(envVars);
            if (isPullRequestEvent) {
                Automation automation = new Automation();
                automation.setPrComment(true);
                coverity.setAutomation(automation);
            } else {
                logger.info(ApplicationConstants.COVERITY_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }
    }

    private void setCoverityInstallDirectory(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY)
                .toString()
                .trim();
        if (!value.isBlank()) {
            Install install = new Install();
            install.setDirectory(value);
            coverity.setInstall(install);
        }
    }

    private void setCoverityPolicyView(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_POLICY_VIEW_KEY)
                .toString()
                .trim();
        if (!value.isBlank()) {
            Policy policy = new Policy();
            policy.setView(value);
            coverity.getConnect().setPolicy(policy);
        }
    }

    private void setBuildCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY)
                .toString()
                .trim();
        if (!value.isBlank()) {
            Build build = new Build();
            build.setCommand(value);
            coverity.setBuild(build);
        }
    }

    private void setCleanCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY)
                .toString()
                .trim();
        if (!value.isBlank()) {
            Clean clean = new Clean();
            clean.setCommand(value);
            coverity.setClean(clean);
        }
    }

    private void setConfigCommand(Map<String, Object> coverityParameters, Coverity coverity) {
        String value = coverityParameters
                .get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY)
                .toString()
                .trim();
        if (!value.isBlank()) {
            Config config = new Config();
            config.setPath(value);
            coverity.setConfig(config);
        }
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> polarisParameters) {
        Project project = null;

        if (polarisParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY)) {
            project = new Project();

            String projectDirectory = polarisParameters
                    .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                    .toString()
                    .trim();
            project.setDirectory(projectDirectory);
        }
        return project;
    }
}
