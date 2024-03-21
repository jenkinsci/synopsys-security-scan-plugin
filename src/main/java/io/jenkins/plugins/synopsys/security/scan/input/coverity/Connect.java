package io.jenkins.plugins.synopsys.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Connect {
    @JsonProperty("url")
    private String url;

    @JsonProperty("user")
    private User user;

    @JsonProperty("project")
    private Project project;

    @JsonProperty("stream")
    private Stream stream;

    @JsonProperty("policy")
    private Policy policy;

    Connect() {
        user = new User();
        project = new Project();
        stream = new Stream();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Stream getStream() {
        return stream;
    }

    public void setStream(Stream stream) {
        this.stream = stream;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }
}
