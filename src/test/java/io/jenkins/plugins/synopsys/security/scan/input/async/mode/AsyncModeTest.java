package io.jenkins.plugins.synopsys.security.scan.input.async.mode;

import static org.junit.jupiter.api.Assertions.*;

import io.jenkins.plugins.synopsys.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.synopsys.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.synopsys.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.synopsys.security.scan.input.srm.SRM;
import org.junit.jupiter.api.Test;

public class AsyncModeTest {
    @Test
    public void testWaitForScanForSRM() {
        SRM srm = new SRM();
        srm.setWaitForScan(true);
        assertEquals(true, srm.isWaitForScan());
    }

    @Test
    public void testWaitForScanForBlackduck() {
        BlackDuck blackDuck = new BlackDuck();
        blackDuck.setWaitForScan(true);
        assertEquals(true, blackDuck.isWaitForScan());
    }

    @Test
    public void testWaitForScanForCoverity() {
        Coverity coverity = new Coverity();
        coverity.setWaitForScan(true);
        assertEquals(true, coverity.isWaitForScan());
    }

    @Test
    public void testWaitForScanForPolaris() {
        Polaris polaris = new Polaris();
        polaris.setWaitForScan(true);
        assertEquals(true, polaris.isWaitForScan());
    }
}
