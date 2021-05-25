package org.keycloak.mtls;

public class MtlsValidationException extends Exception {
    private String validationFailureCause;
    public MtlsValidationException() {
    }

    public MtlsValidationException(String message, String validationFailureCause) {
        super(message);
        this.validationFailureCause = validationFailureCause;
    }

    public String getValidationFailureCause() {
        return validationFailureCause;
    }

    public void setValidationFailureCause(String validationFailureCause) {
        this.validationFailureCause = validationFailureCause;
    }
}
