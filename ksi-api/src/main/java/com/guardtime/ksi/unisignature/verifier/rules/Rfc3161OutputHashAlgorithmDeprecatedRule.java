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
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * This rule verifies if the RFC3161 compatibility record output hash algorithm was deprecated at the time of signing.
 */
public class Rfc3161OutputHashAlgorithmDeprecatedRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(Rfc3161OutputHashAlgorithmDeprecatedRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getRfc3161Record() != null) {
            Date rfc3161AggregationTime = context.getRfc3161Record().getAggregationTime();
            HashAlgorithm hashAlgorithm = context.getSignature().getAggregationHashChains()[0].getInputHash().getAlgorithm();

            if (context.getRfc3161Record().getOutputHash(hashAlgorithm).getAlgorithm().isDeprecated(rfc3161AggregationTime)) {
                logger.info("RFC-3161 record output hash algorithm is deprecated.");
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_17;
    }
}
