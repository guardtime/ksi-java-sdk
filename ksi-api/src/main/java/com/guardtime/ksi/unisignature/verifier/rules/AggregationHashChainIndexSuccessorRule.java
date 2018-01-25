/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Checks that chain index of a aggregation hash chain is successor to it's parent aggregation hash chain index.
 */
public class AggregationHashChainIndexSuccessorRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(AggregationHashChainIndexSuccessorRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] chains = context.getAggregationHashChains();
        List<Long> previousIndex = null;
        for (AggregationHashChain chain : chains) {
            List<Long> currentIndex = chain.getChainIndex();

            if (previousIndex != null) {
                if (!isSuccessorIndex(previousIndex, currentIndex)) {
                    logger.info("Chain index is not the successor to the parent aggregation hash chain index. Invalid chain length. Chain index: {}; Parent chain index: {}", currentIndex, previousIndex);
                    return VerificationResultCode.FAIL;
                }
                if (!isPreviousIndex(previousIndex, currentIndex)) {
                    logger.info("Chain index is not the successor to the parent aggregation hash chain index. Invalid index value. Chain index: {}; Parent chain index: {}", currentIndex, previousIndex);
                    return VerificationResultCode.FAIL;
                }
            }
            previousIndex = currentIndex;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_12;
    }

    private boolean isSuccessorIndex(List<Long> previousIndex, List<Long> currentIndex) {
        return previousIndex.size() - 1 == currentIndex.size();
    }

    private boolean isPreviousIndex(List<Long> previousIndex, List<Long> currentIndex) {
        for (int i = 0; i < currentIndex.size(); i++) {
            if (!currentIndex.get(i).equals(previousIndex.get(i))) {
                return false;
            }
        }
        return true;
    }

}
