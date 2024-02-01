package io.jenkins.plugins.synopsys.security.scan.service.scan;

import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.ErrorCode;
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

    public ScanParametersService(TaskListener listener) {
        this.listener = listener;
    }

    public boolean performScanParameterValidation(Map<String, Object> scanParameters)
        throws PluginExceptionHandler {
        Set<String> securityProducts = getSynopsysSecurityProducts(scanParameters);

        if (securityProducts.contains(SecurityProduct.BLACKDUCK.name())) {
            BlackDuckParametersService blackDuckParametersService = new BlackDuckParametersService(listener);
            if (!blackDuckParametersService.isValidBlackDuckParameters(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_BLACKDUCK_PARAMETERS);
            }
        }
        if (securityProducts.contains(SecurityProduct.COVERITY.name())) {
            CoverityParametersService coverityParametersService = new CoverityParametersService(listener);
            if (!coverityParametersService.isValidCoverityParameters(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_BLACKDUCK_PARAMETERS);
            }
        }
        if (securityProducts.contains(SecurityProduct.POLARIS.name())) {
            PolarisParametersService polarisParametersService = new PolarisParametersService(listener);
            if (!polarisParametersService.isValidPolarisParameters(scanParameters)) {
                throw new PluginExceptionHandler(ErrorCode.INVALID_BLACKDUCK_PARAMETERS);
            }
        }

        return true;
    }

    public Set<String> getSynopsysSecurityProducts(Map<String, Object> scanParameters) {
        String securityPlatform = (String) scanParameters.get(ApplicationConstants.PRODUCT_KEY);

        return Arrays.stream(securityPlatform.split(","))
                .map(String::trim)
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
    }
}
