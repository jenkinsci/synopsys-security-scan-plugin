package io.jenkins.plugins.synopsys.security.scan.global;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import hudson.security.ACL;
import hudson.util.Secret;
import java.util.Collections;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

public class ScanCredentialsHelper {
    public static final Class<StringCredentialsImpl> API_TOKEN_CREDENTIALS_CLASS = StringCredentialsImpl.class;
    public static final CredentialsMatcher API_TOKEN_CREDENTIALS =
            CredentialsMatchers.instanceOf(API_TOKEN_CREDENTIALS_CLASS);
    public static final Class<UsernamePasswordCredentialsImpl> USERNAME_PASSWORD_CREDENTIALS_CLASS =
            UsernamePasswordCredentialsImpl.class;
    public static final CredentialsMatcher USERNAME_PASSWORD_CREDENTIALS =
            CredentialsMatchers.instanceOf(USERNAME_PASSWORD_CREDENTIALS_CLASS);

    public Optional<String> getApiTokenByCredentialsId(String credentialsId) {
        return getApiTokenCredentialsById(credentialsId)
                .map(StringCredentialsImpl::getSecret)
                .map(Secret::getPlainText);
    }

    public Optional<String> getUsernameByCredentialsId(String credentialsId) {
        return getUsernamePasswordCredentialsById(credentialsId).map(UsernamePasswordCredentialsImpl::getUsername);
    }

    public Optional<String> getPasswordByCredentialsId(String credentialsId) {
        return getUsernamePasswordCredentialsById(credentialsId)
                .map(UsernamePasswordCredentialsImpl::getPassword)
                .map(Secret::getPlainText);
    }

    public Optional<UsernamePasswordCredentialsImpl> getUsernamePasswordCredentialsById(String credentialsId) {
        return getCredentialsById(USERNAME_PASSWORD_CREDENTIALS_CLASS, credentialsId);
    }

    public Optional<StringCredentialsImpl> getApiTokenCredentialsById(String credentialsId) {
        return getCredentialsById(API_TOKEN_CREDENTIALS_CLASS, credentialsId);
    }

    public <T extends Credentials> Optional<T> getCredentialsById(Class<T> credentialsType, String credentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();

        if (jenkins == null || StringUtils.isBlank(credentialsId)) {
            return Optional.empty();
        }

        IdMatcher idMatcher = new IdMatcher(credentialsId);

        return CredentialsProvider.lookupCredentials(credentialsType, jenkins, ACL.SYSTEM, Collections.emptyList())
                .stream()
                .filter(idMatcher::matches)
                .findAny();
    }
}
