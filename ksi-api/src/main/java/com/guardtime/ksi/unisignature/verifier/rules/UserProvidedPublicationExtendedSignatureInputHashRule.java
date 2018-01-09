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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Checks that extender response input hash equals with signature aggregation root hash.
 */
public class UserProvidedPublicationExtendedSignatureInputHashRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserProvidedPublicationExtendedSignatureInputHashRule.class);

    @Override
    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        PublicationData userPublication = context.getUserProvidedPublication();
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(userPublication.getPublicationTime());
        DataHash inputHash = extendedCalendarHashChain.getInputHash();
        DataHash aggregationOutputHash = context.getLastAggregationHashChain().getOutputHash();
        if (inputHash.equals(aggregationOutputHash)) {
            return VerificationResultCode.OK;
        }
        LOGGER.info("Invalid extended signature calendar hash chain input hash. Expected {}, found {}", aggregationOutputHash, inputHash);
        return VerificationResultCode.FAIL;
    }

    @Override
    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.PUB_03;
    }
}
