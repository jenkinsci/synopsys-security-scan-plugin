package io.jenkins.plugins.synopsys.security.scan.service.scan.polaris;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Parent;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Prcomment;
import io.jenkins.plugins.synopsys.security.scan.input.project.Project;
import io.jenkins.plugins.synopsys.security.scan.input.project.Source;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

        List<String> invalidParams = getInvalidPolarisParamsForAllJobTypes(polarisParameters);

        if (invalidParams.isEmpty()) {
            logger.info("Polaris parameters are validated successfully");
            return true;
        } else {
            logger.error("Polaris parameters are not valid");
            logger.error("Invalid Polaris parameters: " + invalidParams);
            return false;
        }
    }

    private List<String> getInvalidPolarisParamsForAllJobTypes(Map<String, Object> polarisParameters) {
        List<String> invalidParams = new ArrayList<>();

        Arrays.asList(
                        ApplicationConstants.POLARIS_SERVER_URL_KEY,
                        ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                        ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)
                .forEach(key -> {
                    boolean isKeyValid = polarisParameters.containsKey(key)
                            && polarisParameters.get(key) != null
                            && !polarisParameters.get(key).toString().isEmpty();

                    if (!isKeyValid) {
                        invalidParams.add(key);
                    }
                });

        invalidParams.addAll(getInvalidMandatoryParamsForFreeStyleAndPipeline(polarisParameters));

        return invalidParams;
    }

    private List<String> getInvalidMandatoryParamsForFreeStyleAndPipeline(Map<String, Object> polarisParameters) {
        List<String> invalidParamsForPipelineOrFreeStyle = new ArrayList<>();

        String jobType = Utility.jenkinsJobType(envVars);
        if (!jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            Arrays.asList(
                            ApplicationConstants.POLARIS_APPLICATION_NAME_KEY,
                            ApplicationConstants.POLARIS_PROJECT_NAME_KEY,
                            ApplicationConstants.POLARIS_BRANCH_NAME_KEY)
                    .forEach(key -> {
                        boolean isKeyValid = polarisParameters.containsKey(key)
                                && polarisParameters.get(key) != null
                                && !polarisParameters.get(key).toString().isEmpty();

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

        if (polarisParameters.containsKey(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY)) {
            setAssessmentMode(polarisParameters, polaris);
        }

        return polaris;
    }

    private void setAssessmentTypes(Map<String, Object> polarisParameters, Polaris polaris) {
        String assessmentTypesValue = polarisParameters
                .get(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY)
                .toString()
                .trim();
        if (!assessmentTypesValue.isEmpty()) {
            List<String> assessmentTypes = Stream.of(
                            assessmentTypesValue.toUpperCase().split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
            polaris.getAssessmentTypes().setTypes(assessmentTypes);
        }
    }

    private void setAssessmentMode(Map<String, Object> polarisParameters, Polaris polaris) {
        String assessmentModeValue = polarisParameters
                .get(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY)
                .toString()
                .trim();
        if (!assessmentModeValue.isEmpty()) {
            polaris.getAssessmentTypes().setMode(assessmentModeValue);
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
                setBranchParent(polarisParameters, polaris);
            } else {
                logger.info(ApplicationConstants.POLARIS_PRCOMMENT_INFO_FOR_NON_PR_SCANS);
            }
        }
    }

    private static void setBranchParent(Map<String, Object> polarisParameters, Polaris polaris) {
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
    }

    public Project prepareProjectObjectForBridge(Map<String, Object> polarisParameters) {
        Project project = null;
        Source source = null;

        boolean hasProjectDirectory = polarisParameters.containsKey(ApplicationConstants.PROJECT_DIRECTORY_KEY);
        boolean hasSourceArchive = polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY);
        boolean hasPreserveSymLinks =
                polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY);
        boolean hasSourceExcludes = polarisParameters.containsKey(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY);

        if (hasProjectDirectory || hasSourceArchive || hasPreserveSymLinks || hasSourceExcludes) {
            project = new Project();
            source = new Source();

            if (hasProjectDirectory) {
                String projectDirectory = polarisParameters
                        .get(ApplicationConstants.PROJECT_DIRECTORY_KEY)
                        .toString()
                        .trim();
                project.setDirectory(projectDirectory);
            }

            if (hasSourceArchive) {
                String archive = polarisParameters
                        .get(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY)
                        .toString()
                        .trim();
                source.setArchive(archive);
                project.setSource(source);
            }

            if (hasPreserveSymLinks) {
                Boolean preserveSymLinks =
                        (Boolean) polarisParameters.get(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY);
                source.setPreserveSymLinks(preserveSymLinks);
                project.setSource(source);
            }

            if (hasSourceExcludes) {
                String sourceExcludesValue = polarisParameters
                        .get(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY)
                        .toString()
                        .trim();
                if (!sourceExcludesValue.isEmpty()) {
                    List<String> sourceExcludes = Stream.of(sourceExcludesValue.split(","))
                            .map(String::trim)
                            .collect(Collectors.toList());
                    source.setExcludes(sourceExcludes);
                    project.setSource(source);
                }
            }
        }

        return project;
    }
}
