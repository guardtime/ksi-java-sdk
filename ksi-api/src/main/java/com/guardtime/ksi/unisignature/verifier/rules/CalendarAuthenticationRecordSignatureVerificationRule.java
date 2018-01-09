/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.SignatureData;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.Certificate;

/**
 * Validates calendar authentication record signature. At first X.509 certificate is searched from
 * publications file and when the certificate is found then the PKI signature is validated.
 */
public class CalendarAuthenticationRecordSignatureVerificationRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(CalendarAuthenticationRecordSignatureVerificationRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        CalendarAuthenticationRecord authenticationRecord = context.getCalendarAuthenticationRecord();
        SignatureData signatureData = authenticationRecord.getSignatureData();
        Certificate certificate = context.getCertificate(signatureData.getCertificateId());
        try {
            Signature sig = Signature.getInstance(signatureData.getSignatureType(), BouncyCastleProvider.PROVIDER_NAME);
            sig.initVerify(certificate);
            sig.update(authenticationRecord.getPublicationData().getEncoded());
            if (!sig.verify(signatureData.getSignatureValue())) {
                LOGGER.info("Invalid calendar authentication record signature.");
                return VerificationResultCode.FAIL;
            }
        } catch (GeneralSecurityException e) {
            LOGGER.warn("General PKI security exception occurred when verifying KSI signature. " + e.getMessage(), e);
            return VerificationResultCode.FAIL;
        }


        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.KEY_02;
    }

}
