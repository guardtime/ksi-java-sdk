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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.RFC3161Record;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This rule verifies that if RFC3161 record is present then the calculated output hash (from RFC3161 record) equals to
 * aggregation chain input hash. If RFC3161 record is missing then the status {@link VerificationResultCode#OK} is
 * returned.
 */
public class AggregationChainInputHashVerificationRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregationChainInputHashVerificationRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        KSISignature signature = context.getSignature();
        if (signature.getRfc3161Record() == null) {
            return VerificationResultCode.OK;
        }
        RFC3161Record rfc3161Record = context.getRfc3161Record();

        DataHash inputHash = signature.getAggregationHashChains()[0].getInputHash();
        DataHash rfc3161OutputHash = rfc3161Record.getOutputHash(inputHash.getAlgorithm());

        if (!inputHash.equals(rfc3161OutputHash)) {
            LOGGER.info("Inconsistent RFC3161 and aggregation chain record. Expected aggregation input hash {}, calculated hash from RFC3131 record was {}, ", signature.getAggregationHashChains()[0].getInputHash(), rfc3161OutputHash);
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }



    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_01;
    }


}
