package io.jenkins.plugins.synopsys.security.scan;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.service.ScannerArgumentService;
import io.jenkins.plugins.synopsys.security.scan.service.diagnostics.DiagnosticsService;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class SecurityScanner {
    private final Run<?, ?> run;
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final Launcher launcher;
    private final FilePath workspace;
    private final EnvVars envVars;
    private final ScannerArgumentService scannerArgumentService;

    public SecurityScanner(
            Run<?, ?> run,
            TaskListener listener,
            Launcher launcher,
            FilePath workspace,
            EnvVars envVars,
            ScannerArgumentService scannerArgumentService) {
        this.run = run;
        this.listener = listener;
        this.launcher = launcher;
        this.workspace = workspace;
        this.envVars = envVars;
        this.scannerArgumentService = scannerArgumentService;
        this.logger = new LoggerWrapper(listener);
    }

    public int runScanner(Map<String, Object> scanParams, FilePath bridgeInstallationPath)
            throws PluginExceptionHandler {
        int scanner = -1;

        List<String> commandLineArgs = scannerArgumentService.getCommandLineArgs(scanParams, bridgeInstallationPath);

        logger.info("Executable command line arguments: "
                + commandLineArgs.stream()
                        .map(arg -> arg.concat(" "))
                        .collect(Collectors.joining())
                        .trim());

        try {
            logger.println();
            logger.println(
                    "******************************* %s *******************************",
                    "START EXECUTION OF SYNOPSYS BRIDGE");

            scanner = launcher.launch()
                    .cmds(commandLineArgs)
                    .envs(envVars)
                    .pwd(workspace)
                    .stdout(listener)
                    .quiet(true)
                    .join();
        } catch (Exception e) {
            logger.error(LogMessages.EXCEPTION_OCCURRED_WHILE_INVOKING_SYNOPSYS_BRIDGE, e.getMessage());
            Thread.currentThread().interrupt();
        } finally {
            logger.println(
                    "******************************* %s *******************************",
                    "END EXECUTION OF SYNOPSYS BRIDGE");

            scannerArgumentService.removeTemporaryInputJson(commandLineArgs);

            if (Objects.equals(scanParams.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY), true)) {
                DiagnosticsService diagnosticsService = new DiagnosticsService(
                        run,
                        listener,
                        launcher,
                        envVars,
                        new ArtifactArchiver(ApplicationConstants.ALL_FILES_WILDCARD_SYMBOL));
                diagnosticsService.archiveDiagnostics(
                        workspace.child(ApplicationConstants.BRIDGE_DIAGNOSTICS_DIRECTORY));
            }
        }

        return scanner;
    }
}
