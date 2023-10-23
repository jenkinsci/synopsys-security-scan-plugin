package io.jenkins.plugins.synopsys.security.scan.exception;

public class PluginExceptionHandler extends Exception {
    private static final long serialVersionUID = 3172941819259598261L;

    public PluginExceptionHandler() {
        super();
    }

    public PluginExceptionHandler(String message) {
        super(message);
    }

    public PluginExceptionHandler(Throwable cause) {
        super(cause);
    }

    public PluginExceptionHandler(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
