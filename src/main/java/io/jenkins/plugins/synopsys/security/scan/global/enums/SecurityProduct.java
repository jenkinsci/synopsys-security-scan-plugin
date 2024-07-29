package io.jenkins.plugins.synopsys.security.scan.global.enums;

public enum SecurityProduct {
    BLACKDUCK("Black Duck"),
    COVERITY("Coverity"),
    POLARIS("Polaris"),
    SRM("Software Risk Manager (SRM)");

    private String productLabel;

    SecurityProduct(String productLabel) {
        this.productLabel = productLabel;
    }

    public String getProductLabel() {
        return productLabel;
    }
}
