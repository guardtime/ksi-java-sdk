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
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Verifies if the RFC-3161 record uses internally a hash function that was deprecated at the aggregation time.
 */
public class InternalHashAlgorithmsDeprecatedRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(InternalHashAlgorithmsDeprecatedRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getRfc3161Record() != null) {
            Date rfc3161AggregationTime = context.getRfc3161Record().getAggregationTime();
            if (context.getRfc3161Record().getTstInfoAlgorithm().isDeprecated(rfc3161AggregationTime)
                    || context.getRfc3161Record().getSignedAttributesAlgorithm().isDeprecated(rfc3161AggregationTime)) {
                logger.info("RFC-3161 record internal hash function is deprecated.");
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_14;
    }
}
