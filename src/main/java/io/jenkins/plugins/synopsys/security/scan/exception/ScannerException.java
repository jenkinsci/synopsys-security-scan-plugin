package io.jenkins.plugins.synopsys.security.scan.exception;

public class ScannerException extends Exception {
    private static final long serialVersionUID = 3172941819259598261L;

    public ScannerException() {
        super();
    }

    public ScannerException(String message) {
        super(message);
    }
}
