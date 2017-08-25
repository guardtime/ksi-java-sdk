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
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.LinkMetadata;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This rule verifies that all metadata structures in aggregation hash chain links are valid.
 */
public final class AggregationHashChainLinkMetadataRule extends BaseRule {
    private static final int EXPECTED_PADDING_CONTENT = 0x01;
    private static final int ELEMENT_TYPE_PADDING = 0x1E;

    private static final Logger logger = LoggerFactory.getLogger(AggregationHashChainLinkMetadataRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] aggregationChains = context.getAggregationHashChains();
        for (AggregationHashChain chain : aggregationChains) {
            for (AggregationChainLink link : chain.getChainLinks()) {
                LinkMetadata metadata = link.getMetadata();
                if (metadata == null) {
                    continue; // No metadata, nothing to verify.
                }
                TLVElement linkMetadataRootElement = metadata.getMetadataStructure().getRootElement();

                if (paddingElementMissing(linkMetadataRootElement)) {
                    if (contentCanBeMistakenForHashImprint(linkMetadataRootElement)) {
                        logger.info("Metadata might be hash!");
                        return VerificationResultCode.FAIL;
                    }
                } else if (multiplePaddingElements(linkMetadataRootElement) ||
                        firstChildElementIsNotPadding(linkMetadataRootElement) ||
                        paddingElementHasInvalidFlags(linkMetadataRootElement) ||
                        paddingHasInvalidContent(linkMetadataRootElement)) {
                    logger.info("Metadata can not be determined to be valid!");
                    return VerificationResultCode.FAIL;
                }
            }
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_11;
    }

    private boolean paddingElementMissing(TLVElement rootElement) {
        TLVElement paddingElement = rootElement.getFirstChildElement(ELEMENT_TYPE_PADDING);
        return paddingElement == null;
    }

    private boolean contentCanBeMistakenForHashImprint(TLVElement rootElement) {
        try {
            rootElement.getDecodedDataHash();
            return true;
        } catch (TLVParserException e) {
            // This is what we want, the content doesn't resolve to any known hash.
            return false;
        }
    }

    private boolean multiplePaddingElements(TLVElement rootElement) {
        List<TLVElement> paddingElements = rootElement.getChildElements(ELEMENT_TYPE_PADDING);
        return paddingElements.size() > 1;
    }

    private boolean firstChildElementIsNotPadding(TLVElement rootElement) {
        TLVElement firstChildElement = rootElement.getChildElements().get(0);
        return firstChildElement.getType() != ELEMENT_TYPE_PADDING;
    }

    private boolean paddingElementHasInvalidFlags(TLVElement rootElement) {
        TLVElement paddingElement = rootElement.getFirstChildElement(ELEMENT_TYPE_PADDING);
        return paddingElement.isInputTlv16() || !paddingElement.isForwarded() || !paddingElement.isNonCritical();
    }

    private boolean paddingHasInvalidContent(TLVElement rootElement) throws TLVParserException {
        byte[] paddingContent = rootElement.getFirstChildElement(ELEMENT_TYPE_PADDING).getContent();
        int paddingLength = paddingContent.length;
        int contentLength = rootElement.getContent().length;
        if (contentLength % 2 != 0
                || paddingLength > 2) {
            return true;
        }
        for (byte b : paddingContent) {
            if (b != EXPECTED_PADDING_CONTENT) {
                return true;
            }
        }
        return false;
    }


}
