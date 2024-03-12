package io.jenkins.plugins.synopsys.security.scan.service.diagnostics;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.enums.ReportType;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class UploadReportServiceTest {
    @Mock
    private Run<?, ?> runMock;

    @Mock
    private TaskListener listenerMock;

    @Mock
    private Launcher launcherMock;

    @Mock
    private EnvVars envVarsMock;

    @Mock
    private ArtifactArchiver artifactArchiverMock;

    private UploadReportService uploadReportService;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        when(listenerMock.getLogger()).thenReturn(mock(PrintStream.class));
        when(artifactArchiverMock.getArtifacts()).thenReturn(ApplicationConstants.ALL_FILES_WILDCARD_SYMBOL);
        uploadReportService =
                spy(new UploadReportService(runMock, listenerMock, launcherMock, envVarsMock, artifactArchiverMock));
    }

    @Test
    public void testArchiveDiagnosticsWhenPathExistsShouldArchiveSuccessfully() {
        FilePath homePath = new FilePath(new File(System.getProperty("user.home")));
        FilePath diagnosticsPath = homePath.child("diagnostics");

        try {
            diagnosticsPath.mkdirs();
            assertTrue(diagnosticsPath.exists());

            doNothing()
                    .when(artifactArchiverMock)
                    .perform(eq(runMock), eq(diagnosticsPath), eq(envVarsMock), eq(launcherMock), eq(listenerMock));

            uploadReportService.archiveReports(diagnosticsPath, ReportType.DIAGNOSTIC);
            verify(artifactArchiverMock).perform(runMock, diagnosticsPath, envVarsMock, launcherMock, listenerMock);

            diagnosticsPath.deleteRecursive();
        } catch (IOException | InterruptedException e) {
            System.out.println("Exception occurred during testing for archiveReports method: " + e.getMessage());
        }
    }

    @Test
    public void testArchiveDiagnosticsWhenPathDoesNotExistShouldPrintError() {
        String nonExistingPath = "/path/to/nonexistent";
        FilePath diagnosticsPath = new FilePath(new File(nonExistingPath));

        try {
            assertFalse(diagnosticsPath.exists());

            uploadReportService.archiveReports(diagnosticsPath, ReportType.DIAGNOSTIC);
            verify(artifactArchiverMock, never()).perform(any(), any(), any(), any(), any());
        } catch (IOException | InterruptedException e) {
            System.out.println("Exception occurred during testing for archiveReports method: " + e.getMessage());
        }
    }
}
