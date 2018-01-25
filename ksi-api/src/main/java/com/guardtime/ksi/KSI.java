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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;

import java.io.Closeable;

/**
 * Composite interface for signing, extending, verifying, and publications handling. An instance of this class can be obtained using {@link KSIBuilder} class.
 */
public interface KSI extends Signer, Extender, Reader, Verifier, PublicationsHandler, Closeable {

    /**
     * Verifies the KSI signature.
     *
     * @param context
     *         instance of {@link VerificationContext} to be used to validate the KSI signature.
     * @param policy
     *         policy to be used to verify the KSI signature.
     * @return The verification result ({@link VerificationResult}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    VerificationResult verify(VerificationContext context, Policy policy) throws KSIException;

    /**
     * Verifies the KSI signature. Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         KSI signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy) throws KSIException;

    /**
     * Verifies the KSI signature. Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         KSI signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param publicationData
     *         publication data to be used to verify the signature, may be null.
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy, PublicationData publicationData) throws KSIException;

    /**
     * Verifies the KSI signature. Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         KSI signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param documentHash
     *         the original document hash, may be null.
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash) throws KSIException;

    /**
     * Verifies the KSI signature. Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         KSI signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param documentHash
     *         the original document hash, may be null.
     * @param publicationData
     *         publication data to be used to verify the signature, may be null.
     * @see KSI#verify(VerificationContext, Policy)
     */
    VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash, PublicationData publicationData) throws KSIException;
}
