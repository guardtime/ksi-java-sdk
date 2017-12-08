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
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.SignatureData;
import com.guardtime.ksi.util.Base16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.Certificate;

/**
 * Checks if publications file contains certificate with certificate id present in calendar
 * authentication record.
 */
public class CertificateExistenceRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateExistenceRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        CalendarAuthenticationRecord authenticationRecord = context.getCalendarAuthenticationRecord();
        SignatureData signatureData = authenticationRecord.getSignatureData();
        Certificate certificate = context.getCertificate(signatureData.getCertificateId());
        if (certificate == null) {
            LOGGER.info("Certificate with id {} not present in publications file", Base16.encode(signatureData.getCertificateId()));
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.KEY_01;
    }
}
