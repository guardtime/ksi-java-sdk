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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Verifies that user provided publication time matches with extender response calendar chain shape.
 */
public class UserProvidedPublicationTimeMatchesExtendedResponseRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserProvidedPublicationTimeMatchesExtendedResponseRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        PublicationData userPublication = context.getUserProvidedPublication();
        KSISignature signature = context.getSignature();
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(userPublication.getPublicationTime());
        // check response time
        Date extendedSignaturePublicationTime = extendedCalendarHashChain.getPublicationTime();
        if (!userPublication.getPublicationTime().equals(extendedSignaturePublicationTime)) {
            LOGGER.info("User provided publication time does not match extender response time. Expected {}, got {}", userPublication.getPublicationTime(), extendedSignaturePublicationTime);
            return VerificationResultCode.FAIL;
        }
        // calculate round time and check that it matches with aggregation hash chain aggregation time
        if (!signature.getAggregationTime().equals(extendedCalendarHashChain.getAggregationTime())) {
            LOGGER.info("Signature aggregation hash chain aggregation time does not math with extender registration time. Expected {}, got {}", signature.getAggregationTime(), extendedCalendarHashChain.getAggregationTime());
            return VerificationResultCode.FAIL;
        }

        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.PUB_02;
    }

}
