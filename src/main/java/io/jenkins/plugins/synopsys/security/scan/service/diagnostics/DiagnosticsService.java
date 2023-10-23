package io.jenkins.plugins.synopsys.security.scan.service.diagnostics;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;

public class DiagnosticsService {
    private final Run<?, ?> run;
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final Launcher launcher;
    private final EnvVars envVars;
    private final ArtifactArchiver artifactArchiver;

    public DiagnosticsService(
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

    public void archiveDiagnostics(FilePath diagnosticsPath) {
        try {
            if (diagnosticsPath.exists()) {
                logger.info("Archiving diagnostics jenkins artifact from: " + diagnosticsPath.getRemote());

                artifactArchiver.perform(run, diagnosticsPath, envVars, launcher, listener);
            } else {
                logger.error("Archiving diagnostics failed as diagnostics path not found at: "
                        + diagnosticsPath.getRemote());
                return;
            }
        } catch (Exception e) {
            logger.error("An exception occurred while archiving diagnostics in jenkins artifact: " + e.getMessage());
            Thread.currentThread().interrupt();
            return;
        }

        logger.info("Diagnostics archived successfully in jenkins artifact");
    }
}
