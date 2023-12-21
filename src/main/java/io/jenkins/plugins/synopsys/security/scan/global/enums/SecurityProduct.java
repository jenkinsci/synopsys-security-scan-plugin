package io.jenkins.plugins.synopsys.security.scan.global.enums;

public enum SecurityProduct {
    BLACKDUCK("Black Duck"),
    COVERITY("Coverity"),
    POLARIS("Polaris");

    private String productLabel;

    SecurityProduct(String productLabel) {
        this.productLabel = productLabel;
    }

    public String getProductLabel() {
        return productLabel;
    }
}
