/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import java.util.List;

/**
 * This rule verifies that user provided input hash level is less than or equal to first aggregation hash chain's first
 * link's level corrector value.
 */
public class InputHashLevelVerificationRule extends BaseRule {

    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        Long userSuppliedLevel = context.getInputHashLevel();
        if (userSuppliedLevel == null) {
            return VerificationResultCode.OK;
        }
        KSISignature signature = context.getSignature();
        AggregationHashChain[] aggregationHashChains = signature.getAggregationHashChains();
        AggregationHashChain firstChain = aggregationHashChains[0];
        List<AggregationChainLink> chainLinks = firstChain.getChainLinks();
        AggregationChainLink firstLink = chainLinks.get(0);
        Long levelCorrection = firstLink.getLevelCorrection();
        return userSuppliedLevel <= levelCorrection ? VerificationResultCode.OK : VerificationResultCode.FAIL;
    }

    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_3;
    }
}
