package io.jenkins.plugins.synopsys.security.scan.input.scm.github;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Github {
    @JsonProperty("user")
    private User user;

    @JsonProperty("repository")
    private Repository repository;

    @JsonProperty("host")
    private Host host;

    public Github() {
        user = new User();
        repository = new Repository();
        host = new Host();
    }

    public User getUser() {
        return user;
    }

    public Repository getRepository() {
        return repository;
    }

    public Host getHost() {
        return host;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setRepository(Repository repository) {
        this.repository = repository;
    }

    public void setHost(Host host) {
        this.host = host;
    }
}
