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
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * This rule verifies that the legacy client identifier <ul> <li>value is exactly 29 octets;</li> <li>first two octets
 * are 03 and 00;</li> <li>the value of the third octet (at most 25) defines the length of the embedded name and is
 * followed by that many octets of an UTF-8 string.</li> <li>the value is padded with 00 octets to the final length
 * (note that at least one padding octet will exist in any valid structure)</li> </ul>
 */
public class AggregationHashChainLegacyIdRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationHashChainLegacyIdRule.class);

    private static final int LEGACY_ID_LENGTH = 29;
    private static final byte[] LEGACY_ID_PREFIX = new byte[]{0x03, 0x00};
    private static final int LEGACY_ID_OCTET_STRING_MAX_LENGTH = 25;

    @Override
    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        AggregationHashChain[] chains = context.getAggregationHashChains();
        for (AggregationHashChain chain : chains) {
            List<AggregationChainLink> links = chain.getChainLinks();
            for (AggregationChainLink link : links) {
                byte[] legacyId = link.getLegacyId();
                if (legacyId != null) {
                    return verifyLegacyId(legacyId);
                }
            }
        }
        return VerificationResultCode.OK;
    }

    private VerificationResultCode verifyLegacyId(byte[] legacyId) {
        if (legacyId.length != LEGACY_ID_LENGTH) {
            LOGGER.info("Invalid legacyId length.");
            return VerificationResultCode.FAIL;
        }

        if (!Arrays.equals(LEGACY_ID_PREFIX, Arrays.copyOfRange(legacyId, 0, 2))) {
            LOGGER.info("Invalid legacyId prefix.");
            return VerificationResultCode.FAIL;
        }
        int length = Util.toShort(legacyId, 1);
        if (length > LEGACY_ID_OCTET_STRING_MAX_LENGTH) {
            LOGGER.info("Invalid legacyId embedded data length.");
            return VerificationResultCode.FAIL;
        }

        int contentLength = length + 3;
        if (!Arrays.equals(new byte[LEGACY_ID_LENGTH - contentLength], Arrays.copyOfRange(legacyId, contentLength, legacyId.length))) {
            LOGGER.info("Invalid legacyId padding.");
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    @Override
    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_11;
    }

}
