/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.SignatureData;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.util.Base16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Checks if certificate was valid at aggregation time.
 */

public class CertificateValidityRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateValidityRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        Date validAt = context.getSignature().getAggregationTime();

        SignatureData signatureData = context.getCalendarAuthenticationRecord().getSignatureData();
        Certificate certificate = context.getCertificate(signatureData.getCertificateId());
        if (certificate instanceof X509Certificate) {
            try {
                ((X509Certificate) certificate).checkValidity(validAt);
                return VerificationResultCode.OK;
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                LOGGER.info("Certificate id {} was not valid at the aggregation time {}",
                        Base16.encode(signatureData.getCertificateId()), validAt);
            }
        }

        LOGGER.info("Unable to check certificate validity, id = {}", Base16.encode(signatureData.getCertificateId()));
        return VerificationResultCode.FAIL;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.KEY_03;
    }
}
