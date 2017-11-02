/*
 * Copyright 2017 Guardtime, Inc.
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
import com.guardtime.ksi.unisignature.CalendarHashChainLink;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Verifies that calendar hash chain aggregation(derived from the right link) hash algorithms were
 * obsolete at the publication time. If calendar hash chain is missing then status {@link
 * VerificationResultCode#OK} will be returned.
 */
public class CalendarHashChainAggregationAlgorithmObsoleteRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(CalendarHashChainAggregationAlgorithmObsoleteRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getCalendarHashChain() == null) {
            return VerificationResultCode.OK;
        }

        Date publicationTime = context.getSignature().getPublicationTime();
        for (CalendarHashChainLink link : context.getCalendarHashChain().getChainLinks()) {
            if (link.isRightLink() && link.getDataHash().getAlgorithm().isObsolete(publicationTime)) {
                logger.info("Calendar hash chain contains obsolete aggregation algorithm {} at publication time {}",
                        link.getDataHash().getAlgorithm(), publicationTime);
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_16;
    }

}
