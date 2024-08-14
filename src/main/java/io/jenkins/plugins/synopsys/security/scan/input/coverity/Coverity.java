package io.jenkins.plugins.synopsys.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.AsyncMode;
import io.jenkins.plugins.synopsys.security.scan.input.blackduck.Install;

public class Coverity extends AsyncMode {
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

    @JsonProperty("build")
    private Build build;

    @JsonProperty("clean")
    private Clean clean;

    @JsonProperty("config")
    private Config config;

    @JsonProperty("args")
    private String args;

    @JsonProperty("execution")
    private Execution execution;

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

    public Build getBuild() {
        return build;
    }

    public void setBuild(Build build) {
        this.build = build;
    }

    public Clean getClean() {
        return clean;
    }

    public void setClean(Clean clean) {
        this.clean = clean;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public String getArgs() {
        return args;
    }

    public void setArgs(String args) {
        this.args = args;
    }

    public Execution getExecution() {
        return execution;
    }

    public void setExecution(Execution execution) {
        this.execution = execution;
    }
}
