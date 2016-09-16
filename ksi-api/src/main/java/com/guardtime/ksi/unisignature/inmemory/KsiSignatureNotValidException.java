package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;

public class KsiSignatureNotValidException extends KSIException {

    private KSISignature signature;
    private VerificationResult verificationResult;

    public KsiSignatureNotValidException(InMemoryKsiSignature signature, VerificationResult verificationResult) {
        super("Invalid KSI signature: " + verificationResult.getErrorCode() + "('"+verificationResult.getErrorCode().getMessage()+"')");
        this.signature = signature;
        this.verificationResult = verificationResult;
    }

    public KSISignature getSignature() {
        return signature;
    }

    public VerificationResult getVerificationResult() {
        return verificationResult;
    }
}
