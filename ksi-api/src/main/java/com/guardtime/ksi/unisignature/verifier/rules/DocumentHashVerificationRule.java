/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.KSISignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies document hash. If RFC3161 record is present then the document hash must equal to RFC3161
 * input hash. If RFC3161 record isn't present then document hash must equal to first aggregation hash chain input hash.
 * If document hash isn't provided the status {@link VerificationResultCode#OK} will be returned.
 */
public class DocumentHashVerificationRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(DocumentHashVerificationRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        DataHash documentHash = context.getDocumentHash();
        if (documentHash == null) {
            return VerificationResultCode.OK;
        }
        KSISignature signature = context.getSignature();
        DataHash inputHash;
        if (signature.getRfc3161Record() != null) {
            inputHash = signature.getRfc3161Record().getInputHash();
        } else {
            inputHash = signature.getAggregationHashChains()[0].getInputHash();
        }
        if (!documentHash.equals(inputHash)) {
            LOGGER.info("Invalid document hash. Expected {}, found {}", documentHash, inputHash);
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_01;
    }

}
