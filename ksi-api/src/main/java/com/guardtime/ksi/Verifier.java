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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;

/**
 * Verifying a KSI signature. An instance of this class can be obtained using {@link SignatureVerifier} class.
 */
public interface Verifier {

    /**
     * Verifies the KSI signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to be verified.
     * @param policy
     *         context aware policy {@link ContextAwarePolicy} to be used to verify the signature.
     * @return The verification result ({@link VerificationResult}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    VerificationResult verify(KSISignature signature, ContextAwarePolicy policy) throws KSIException;

    /**
     * Verifies the KSI signature. User provided document hash is compared against the data hash
     * within the KSI signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to be verified.
     * @param documentHash
     *         instance of {@link DataHash} to be verified against the signature.
     * @param policy
     *         context aware policy {@link ContextAwarePolicy} to be used to verify the signature.
     * @return The verification result ({@link VerificationResult}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    VerificationResult verify(KSISignature signature, DataHash documentHash, ContextAwarePolicy policy) throws KSIException;

    /**
     * Verifies the KSI signature. User provided document hash and level are compared against the values
     * within the KSI signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to be verified.
     * @param documentHash
     *         instance of {@link DataHash} to be verified against the signature.
     * @param level
     *         local aggregation tree height.
     * @param policy
     *         context aware policy {@link ContextAwarePolicy} to be used to verify the signature.
     * @return The verification result ({@link VerificationResult}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    VerificationResult verify(KSISignature signature, DataHash documentHash, Long level, ContextAwarePolicy policy)
            throws KSIException;

}
