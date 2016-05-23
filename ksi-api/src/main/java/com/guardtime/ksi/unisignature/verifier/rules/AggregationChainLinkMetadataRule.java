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
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.SignatureMetadata;
import com.guardtime.ksi.unisignature.inmemory.LinkMetadata;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * This rule verifies that all aggregation hash chains are consistent (e.g previous aggregation output hash equals to
 * current aggregation chain input hash).
 */
public final class AggregationChainLinkMetadataRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChainConsistencyRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] aggregationChains = context.getAggregationHashChains();
        for (AggregationHashChain chain : aggregationChains) {
            for(AggregationChainLink link : chain.getChainLinks()) {
                SignatureMetadata metadata = link.getMetadata();
                if(metadata == null) continue; // No metadata, nothing to verify.
                LinkMetadata linkMetadata = (LinkMetadata) metadata;
                // TODO: Do the stuff for padding verification:
                // it must be first element in metadata
                TLVElement paddingElement = linkMetadata.getRootElement().getChildElements().get(0);
                if(paddingElement.getType() != LinkMetadata.ELEMENT_TYPE_PADDING) {
                    // NOK!
                }

                // it must be TLV8
                // it must have N and F flags set
                if(!paddingElement.isTlv16() && paddingElement.isForwarded() && !paddingElement.isNonCritical()) {
                    // it must have a value of 01 or 0101
                    byte[] expectedContent = new byte[]{0x01, 0x01}; // TODO: construct this based on metadata length
                    if(Arrays.equals(paddingElement.getContent(), expectedContent)) {
                        // everything is OK
                    } else {
                        // NOK!
                    }
                } else {
                    // NOK!
                }
            }
            LOGGER.info("");
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_2; // TODO: Correct error code
    }


}
