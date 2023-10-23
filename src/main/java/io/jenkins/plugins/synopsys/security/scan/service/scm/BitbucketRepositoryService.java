package io.jenkins.plugins.synopsys.security.scan.service.scm;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketApi;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketRepository;
import hudson.model.TaskListener;
import io.jenkins.plugins.synopsys.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.synopsys.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.synopsys.security.scan.global.LogMessages;
import io.jenkins.plugins.synopsys.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.synopsys.security.scan.global.Utility;
import io.jenkins.plugins.synopsys.security.scan.input.bitbucket.Bitbucket;
import io.jenkins.plugins.synopsys.security.scan.input.bitbucket.Pull;
import io.jenkins.plugins.synopsys.security.scan.input.bitbucket.Repository;
import java.util.Map;

public class BitbucketRepositoryService {
    private final LoggerWrapper logger;

    public BitbucketRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Bitbucket fetchBitbucketRepositoryDetails(
            Map<String, Object> scanParameters,
            BitbucketSCMSource bitbucketSCMSource,
            Integer projectRepositoryPullNumber,
            boolean isFixPrOrPrComment)
            throws PluginExceptionHandler {

        String bitbucketToken = (String) scanParameters.get(ApplicationConstants.BITBUCKET_TOKEN_KEY);
        if (Utility.isStringNullOrBlank(bitbucketToken) && isFixPrOrPrComment) {
            logger.error(LogMessages.NO_BITBUCKET_TOKEN_FOUND);
            throw new PluginExceptionHandler(LogMessages.NO_BITBUCKET_TOKEN_FOUND);
        }

        BitbucketApi bitbucketApiFromSCMSource = bitbucketSCMSource.buildBitbucketClient(
                bitbucketSCMSource.getRepoOwner(), bitbucketSCMSource.getRepository());

        BitbucketRepository bitbucketRepository = null;
        try {
            bitbucketRepository = bitbucketApiFromSCMSource.getRepository();
        } catch (Exception e) {
            logger.error(
                    "An exception occurred while getting the BitbucketRepository from BitbucketApi: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        String serverUrl = bitbucketSCMSource.getServerUrl();
        String repositoryName = null;
        String projectKey = null;

        if (bitbucketRepository != null) {
            repositoryName = bitbucketRepository.getRepositoryName();
            projectKey = bitbucketRepository.getProject().getKey();
        }

        return createBitbucketObject(
                serverUrl, bitbucketToken, projectRepositoryPullNumber, repositoryName, projectKey);
    }

    public static Bitbucket createBitbucketObject(
            String serverUrl,
            String bitbucketToken,
            Integer projectRepositoryPullNumber,
            String repositoryName,
            String projectKey) {
        Bitbucket bitbucket = new Bitbucket();
        bitbucket.getApi().setUrl(serverUrl);
        bitbucket.getApi().setToken(bitbucketToken);

        Pull pull = new Pull();
        pull.setNumber(projectRepositoryPullNumber);

        Repository repository = new Repository();
        repository.setName(repositoryName);
        repository.setPull(pull);

        bitbucket.getProject().setKey(projectKey);
        bitbucket.getProject().setRepository(repository);

        return bitbucket;
    }
}
