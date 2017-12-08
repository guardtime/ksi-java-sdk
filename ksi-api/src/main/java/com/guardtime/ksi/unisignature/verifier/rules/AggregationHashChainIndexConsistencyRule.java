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
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Verifies that aggregation chain indices are matching corresponding aggregation chains (e.g all left and
 * right links are correctly defined in the chain index).
 */
public final class AggregationHashChainIndexConsistencyRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChainIndexConsistencyRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] aggregationChains = context.getAggregationHashChains();

        for (AggregationHashChain chain : aggregationChains) {
            int size = chain.getChainIndex().size();
            long index = chain.getChainIndex().get(size - 1);
            long chainToIndex = 0;

            List<AggregationChainLink> links = chain.getChainLinks();
            for (int i = 0; i < links.size(); i++) {
                if (links.get(i).isLeft()) {
                    chainToIndex |= 1L << i;
                }
            }
            chainToIndex |= 1L << links.size();

            if (index != chainToIndex) {
                LOGGER.info("Chain index {} does not match corresponding chain {}", index, chainToIndex);
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_10;
    }
}
