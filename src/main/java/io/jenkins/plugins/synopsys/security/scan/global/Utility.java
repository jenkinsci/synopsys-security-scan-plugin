package io.jenkins.plugins.synopsys.security.scan.global;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;

public class Utility {

    public static String getDirectorySeparator(FilePath workspace, TaskListener listener) {
        String os = getAgentOs(workspace, listener);

        if (os != null && os.contains("win")) {
            return "\\";
        } else {
            return "/";
        }
    }

    public static String getAgentOs(FilePath workspace, TaskListener listener) {
        String os = null;
        LoggerWrapper logger = new LoggerWrapper(listener);

        if (workspace.isRemote()) {
            try {
                os = workspace.act(new OsNameTask());
            } catch (IOException | InterruptedException e) {
                logger.error("An exception occurred while fetching the OS information for the agent node: "
                        + e.getMessage());
                Thread.currentThread().interrupt();
            }
        } else {
            os = System.getProperty("os.name").toLowerCase();
        }

        return os;
    }

    public static void removeFile(String filePath, FilePath workspace, TaskListener listener) {
        LoggerWrapper logger = new LoggerWrapper(listener);
        try {
            FilePath file = new FilePath(workspace.getChannel(), filePath);
            file = file.absolutize();

            if (file.exists()) {
                file.delete();
            }
        } catch (IOException | InterruptedException e) {
            logger.error("An exception occurred while deleting file: " + e.getMessage());
            Thread.currentThread().interrupt();
        }
    }

    public static boolean isStringNullOrBlank(String str) {
        return str == null || str.isBlank() || str.equals("null");
    }

    public static HttpURLConnection getHttpURLConnection(URL url, EnvVars envVars, LoggerWrapper logger) {
        try {
            String proxy = getProxy(url, envVars, logger);
            if (proxy.equals(ApplicationConstants.NO_PROXY)) {
                return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            } else {
                URL proxyURL = new URL(proxy);

                HttpURLConnection connection = (HttpURLConnection) url.openConnection(
                        new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyURL.getHost(), proxyURL.getPort())));
                setDefaultProxyAuthenticator(proxyURL.getUserInfo());

                return connection;
            }
        } catch (IOException e) {
            logger.error("An exception occurred while getting HttpURLConnection: " + e.getMessage());
        }

        return null;
    }

    public static String getProxy(URL url, EnvVars envVars, LoggerWrapper logger) throws IOException {
        String noProxy = getEnvOrSystemProxyDetails(ApplicationConstants.NO_PROXY, envVars);
        if (!isStringNullOrBlank(noProxy)) {
            logger.info("Found NO_PROXY configuration - " + noProxy);
            String[] noProxies = noProxy.split(",");

            for (String noProxyHost : noProxies) {
                if (noProxyHost.startsWith("*") && noProxyHost.length() == 1) {
                    return ApplicationConstants.NO_PROXY;
                } else if (noProxyHost.startsWith("*") && noProxyHost.length() > 2) {
                    noProxyHost = noProxyHost.substring(2);
                    if (url.toString().contains(noProxyHost)) {
                        return ApplicationConstants.NO_PROXY;
                    }
                }
            }
        }

        return getProxyValue(envVars, logger);
    }

    public static String getProxyValue(EnvVars envVars, LoggerWrapper logger) throws MalformedURLException {
        String httpsProxy = getEnvOrSystemProxyDetails(ApplicationConstants.HTTPS_PROXY, envVars);
        if (!isStringNullOrBlank(httpsProxy)) {
            logger.info("Found HTTPS_PROXY configuration - " + getMaskedProxyUrl(httpsProxy));
            return httpsProxy;
        }

        String httpProxy = getEnvOrSystemProxyDetails(ApplicationConstants.HTTP_PROXY, envVars);
        if (!isStringNullOrBlank(httpProxy)) {
            logger.info("Found HTTP_PROXY configuration - " + getMaskedProxyUrl(httpProxy));
            return httpProxy;
        }

        return ApplicationConstants.NO_PROXY;
    }

    public static String getEnvOrSystemProxyDetails(String proxyType, EnvVars envVars) {
        String proxyDetails = envVars.get(proxyType);
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = envVars.get(proxyType.toLowerCase());
        }
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = System.getenv(proxyType);
        }
        if (isStringNullOrBlank(proxyDetails)) {
            proxyDetails = System.getenv(proxyType.toLowerCase());
        }

        return proxyDetails;
    }

    public static void setDefaultProxyAuthenticator(String userInfo) {
        if (!isStringNullOrBlank(userInfo)) {
            String[] userInfoArray = userInfo.split(":");
            if (userInfoArray.length == 2) {
                Authenticator.setDefault(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(userInfoArray[0], userInfoArray[1].toCharArray());
                    }
                });
            }
        }
    }

    private static String getMaskedProxyUrl(String proxyUrlString) throws MalformedURLException {
        URL proxyUrl = new URL(proxyUrlString);
        String userInfo = proxyUrl.getUserInfo();
        if (!isStringNullOrBlank(userInfo) && userInfo.split(":").length > 1) {
            return proxyUrlString.replace(userInfo.split(":")[1], "*****");
        }

        return proxyUrlString;
    }
}
