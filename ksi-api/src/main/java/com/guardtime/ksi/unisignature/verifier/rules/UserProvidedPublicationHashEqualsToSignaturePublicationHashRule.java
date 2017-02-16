package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

/**
 * This rule is used verify that user provided publication data hash equals to signature publication record data hash.
 */
public class UserProvidedPublicationHashEqualsToSignaturePublicationHashRule extends BaseRule {

    @Override
    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        DataHash signaturePublicationRecordHash = context.getPublicationRecord().getPublicationData().getPublicationDataHash();
        DataHash publicationDataHash = context.getUserProvidedPublication().getPublicationDataHash();
        if (!signaturePublicationRecordHash.equals(publicationDataHash)) {
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    @Override
    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.PUB_04;
    }
}
