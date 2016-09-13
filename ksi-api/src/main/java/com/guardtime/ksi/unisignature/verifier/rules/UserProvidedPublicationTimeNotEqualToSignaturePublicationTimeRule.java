package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import java.util.Date;

/**
 * This rule is used verify that user provided publication time does not equal to signature publication time
 */
public class UserProvidedPublicationTimeNotEqualToSignaturePublicationTimeRule extends BaseRule {

    @Override
    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        Date registrationTime = context.getPublicationRecord().getPublicationTime();
        Date userPublicationTime = context.getUserProvidedPublication().getPublicationTime();
        if (registrationTime.equals(userPublicationTime)) {
            return VerificationResultCode.NA;
        }
        return VerificationResultCode.OK;
    }

    @Override
    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_2;
    }

}
