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
 * Verifies that the hash algorithm of the input hash of the signature (input hash of the first aggregation hash chain or
 * if present the input hash of the RFC-3161 record) is deprecated at the aggregation time.
 */
public class SignatureInputHashAlgorithmDeprecatedRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(SignatureInputHashAlgorithmDeprecatedRule.class);

    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        Date aggregationTime = context.getSignature().getAggregationTime();
        HashAlgorithm algorithm = context.getSignature().getInputHash().getAlgorithm();
        if (algorithm.isDeprecated(aggregationTime)) {
            logger.info("Signature input hash algorithm {} is deprecated.", algorithm.getName());
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_13;
    }
}
