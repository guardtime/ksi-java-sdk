package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;

public class InvalidSignatureContentException extends KSIException {

    private KSISignature signature;
    private VerificationResult verificationResult;

    public InvalidSignatureContentException(InMemoryKsiSignature signature, VerificationResult verificationResult) {
        super("Signature (inputHash:" + signature.getInputHash() + ", extended=" + signature.isExtended() + ") is invalid: " + verificationResult.getErrorCode() + "('" + verificationResult.getErrorCode().getMessage() + "')");
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
