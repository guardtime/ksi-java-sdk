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
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This rule verifies that aggregation chain indices are matching corresponding aggregation chains (e.g all left and
 * right links are correctly defined in the chain index).
 */
public final class AggregationHashChainIndexConsistencyRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChainIndexConsistencyRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] aggregationChains = context.getAggregationHashChains();

        for (AggregationHashChain chain : aggregationChains) {
            List<Long> chainIndexList = chain.getChainIndex();
            String chainIndex = Long.toBinaryString(chainIndexList.get(chainIndexList.size() - 1));
            String chainToChainIndex = convertChainToChainIndex(chain);

            if (!chainIndex.equals(chainToChainIndex)) {
                LOGGER.info("Chain index {} does not match corresponding chain {}", chainIndex, chainToChainIndex);
                return VerificationResultCode.FAIL;
            }
        }
        return VerificationResultCode.OK;
    }

    private String convertChainToChainIndex(AggregationHashChain chain) {
        StringBuilder chainIndex = new StringBuilder();
        for (AggregationChainLink link : chain.getChainLinks()) {
            chainIndex.append(link.isLeft() ? "1" : "0");
        }
        return chainIndex.append("1").reverse().toString();
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_10;
    }


}
