package io.jenkins.plugins.synopsys.security.scan.input.blackduck;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.report.Reports;

public class BlackDuck {
    @JsonProperty("url")
    private String url;

    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("token")
    private String token;

    @JsonProperty("install")
    private Install install;

    @JsonProperty("scan")
    private Scan scan;

    @JsonProperty("automation")
    private Automation automation;

    @JsonProperty("download")
    private Download download;

    @JsonProperty("reports")
    private Reports reports;

    public BlackDuck() {
        scan = new Scan();
        automation = new Automation();
        install = new Install();
        reports = new Reports();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setInstall(Install install) {
        this.install = install;
    }

    public Scan getScan() {
        return scan;
    }

    public Install getInstall() {
        return install;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }

    public Automation getAutomation() {
        return automation;
    }

    public void setAutomation(Automation automation) {
        this.automation = automation;
    }

    public Download getDownload() {
        return download;
    }

    public void setDownload(final Download download) {
        this.download = download;
    }

    public Reports getReports() {
        return reports;
    }

    public void setReports(Reports reports) {
        this.reports = reports;
    }
}
