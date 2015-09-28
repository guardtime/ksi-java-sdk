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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This rule verifies that all aggregation hash chains are consistent (e.g previous aggregation output hash equals to
 * current aggregation chain input hash).
 */
public final class AggregationHashChainConsistencyRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChainConsistencyRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] aggregationChains = context.getAggregationHashChains();
        DataHash previousHash = null;
        for (AggregationHashChain chain : aggregationChains) {
            if (previousHash == null) {
                previousHash = chain.getOutputHash();
            } else {
                if (!previousHash.equals(chain.getInputHash())) {
                    LOGGER.info("Previous aggregation hash chain output {} does not match current input {}" +previousHash, chain.getInputHash());
                    return VerificationResultCode.FAIL;
                }
                previousHash = chain.getOutputHash();
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_01;
    }


}
