package io.jenkins.plugins.synopsys.security.scan.service.diagnostics;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.enums.ReportType;

public class UploadReportService {
    private final Run<?, ?> run;
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final Launcher launcher;
    private final EnvVars envVars;
    private final ArtifactArchiver artifactArchiver;

    public UploadReportService(
            Run<?, ?> run,
            TaskListener listener,
            Launcher launcher,
            EnvVars envVars,
            ArtifactArchiver artifactArchiver) {
        this.run = run;
        this.listener = listener;
        this.logger = new LoggerWrapper(listener);
        this.launcher = launcher;
        this.envVars = envVars;
        this.artifactArchiver = artifactArchiver;
    }

    public void archiveReports(FilePath reportsPath, ReportType reportType) {
        try {
            if (reportsPath.exists()) {
                logger.info("Archiving " + reportType.name() + " jenkins artifact from: " + reportsPath.getRemote());

                artifactArchiver.perform(run, reportsPath, envVars, launcher, listener);
            } else {
                logger.error("Archiving " + reportType.name() + " failed as " + reportType.name()
                        + " path not found at: " + reportsPath.getRemote());
                return;
            }
        } catch (Exception e) {
            logger.error("An exception occurred while archiving " + reportType.name() + " in jenkins artifact: "
                    + e.getMessage());
            Thread.currentThread().interrupt();
            return;
        }

        logger.info(reportType.name() + " archived successfully in jenkins artifact");
    }
}
