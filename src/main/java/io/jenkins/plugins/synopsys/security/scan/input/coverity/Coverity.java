package io.jenkins.plugins.synopsys.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Install;

public class Coverity {
    @JsonProperty("connect")
    private Connect connect;

    @JsonProperty("install")
    private Install install;

    @JsonProperty("automation")
    private Automation automation;

    @JsonProperty("version")
    private String version;

    @JsonProperty("local")
    private Boolean local;

    public Coverity() {
        connect = new Connect();
    }

    public Connect getConnect() {
        return connect;
    }

    public void setConnect(Connect connect) {
        this.connect = connect;
    }

    public Install getInstall() {
        return install;
    }

    public void setInstall(Install install) {
        this.install = install;
    }

    public Automation getAutomation() {
        return automation;
    }

    public void setAutomation(Automation automation) {
        this.automation = automation;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Boolean isLocal() {
        return local;
    }

    public void setLocal(Boolean local) {
        this.local = local;
    }
}
