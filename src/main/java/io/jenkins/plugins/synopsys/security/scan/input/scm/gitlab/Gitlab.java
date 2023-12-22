package io.jenkins.plugins.synopsys.security.scan.input.scm.gitlab;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.synopsys.security.scan.input.github.Host;

public class Gitlab {

    @JsonProperty("api")
    private Api api;
    @JsonProperty("user")
    private User user;
    @JsonProperty("repository")
    private Repository repository;

    public Gitlab() {
        api = new Api();
        user = new User();
        repository = new Repository();
    }

    public Api getApi() {
        return api;
    }

    public void setApi(Api api) {
        this.api = api;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Repository getRepository() {
        return repository;
    }

    public void setRepository(Repository repository) {
        this.repository = repository;
    }
}
