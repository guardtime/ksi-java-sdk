/*
 * Copyright 2013-2015 Guardtime, Inc.
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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This rule is used to check if keyless signature contains publication record or not. If publication record is missing
 * then status {@link VerificationResultCode#OK} will be returned.
 */
public class SignaturePublicationRecordPublicationHashRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignaturePublicationRecordPublicationHashRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getPublicationRecord() == null) {
            return VerificationResultCode.OK;
        }

        CalendarHashChain calendarHashChain = context.getCalendarHashChain();
        PublicationData publicationRecordPublicationData = context.getPublicationRecord().getPublicationData();
        if (calendarHashChain.getOutputHash().equals(publicationRecordPublicationData.getPublicationDataHash())) {
            return VerificationResultCode.OK;
        }
        LOGGER.info("Invalid publication record publication hash. Expected '{}', found '{}'", calendarHashChain.getOutputHash(), publicationRecordPublicationData.getPublicationDataHash());
        return VerificationResultCode.FAIL;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_09;
    }
}
