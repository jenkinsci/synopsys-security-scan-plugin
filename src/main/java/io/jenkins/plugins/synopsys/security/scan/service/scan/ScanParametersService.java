package io.jenkins.plugins.synopsys.security.scan.service.scan;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.synopsys.security.scan.service.scan.blackduck.BlackDuckParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.synopsys.security.scan.service.scan.polaris.PolarisParametersService;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ScanParametersService {
    private final TaskListener listener;
    private final EnvVars envVars;

    public ScanParametersService(TaskListener listener, EnvVars envVars) {
        this.listener = listener;
        this.envVars = envVars;
    }

    public boolean isValidScanParameters(Map<String, Object> scanParameters) {
        Set<String> securityProducts = getSynopsysSecurityProducts(scanParameters);

        boolean isValidBlackDuckParameters = true;
        boolean isValidCoverityParameters = true;
        boolean isValidPolarisParameters = true;

        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())) {
            BlackDuckParametersService blackDuckParametersService = new BlackDuckParametersService(listener);
            isValidBlackDuckParameters = blackDuckParametersService.isValidBlackDuckParameters(scanParameters);
        }
        if (securityProducts.contains(SecurityProduct.COVERITY.name())) {
            CoverityParametersService coverityParametersService = new CoverityParametersService(listener, envVars);
            isValidCoverityParameters = coverityParametersService.isValidCoverityParameters(scanParameters);
        }
        if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            PolarisParametersService polarisParametersService = new PolarisParametersService(listener);
            isValidPolarisParameters = polarisParametersService.isValidPolarisParameters(scanParameters);
        }

        return isValidBlackDuckParameters && isValidCoverityParameters && isValidPolarisParameters;
    }

    public Set<String> getSynopsysSecurityProducts(Map<String, Object> scanParameters) {
        String securityPlatform = (String) scanParameters.get(ApplicationConstants.PRODUCT_KEY);

        return Arrays.stream(securityPlatform.split(","))
                .map(String::trim)
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
    }
}
