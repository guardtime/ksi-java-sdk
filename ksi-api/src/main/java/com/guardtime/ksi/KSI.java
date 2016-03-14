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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;

import java.io.Closeable;
import java.io.File;
import java.io.InputStream;

/**
 * An instance of this class can be obtained using {@link KSIBuilder} class.
 */
public interface KSI extends Closeable {

    /**
     * This method can be used to createSignature keyless signature from input stream.
     *
     * @param input
     *         the {@link InputStream} to createSignature from. must not be null.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g file contains invalid TLV structures)
     */
    KSISignature read(InputStream input) throws KSIException;

    /**
     * This method can be used to convert byte array to {@link KSISignature} instance.
     *
     * @param bytes
     *         bytes to createSignature. must not be null.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g file contains invalid TLV structures)
     */
    KSISignature read(byte[] bytes) throws KSIException;

    /**
     * This method can be used to createSignature {@link KSISignature} from file.
     *
     * @param file
     *         file to createSignature
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g file contains invalid TLV structures)
     */
    KSISignature read(File file) throws KSIException;

    /**
     * This method is used to sign data hash.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign. not null.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature sign(DataHash dataHash) throws KSIException;

    /**
     * This method is used to sign a file. Uses hash algorithm defined by method {@link
     * KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param file
     *         file to sign. not null.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature sign(File file) throws KSIException;

    /**
     * This method is used to sign a byte array. Uses hash algorithm defined by method {@link
     * KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param bytes
     *         bytes to sign. not null.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature sign(byte[] bytes) throws KSIException;

    /**
     * This method is used to sign data hash asynchronously. Use method {@link Future#getResult()} to get keyless
     * signature.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign. not null.
     * @return instance of {@link Future}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncSign(DataHash dataHash) throws KSIException;

    /**
     * This method is used to sign a file asynchronously. Use method {@link Future#getResult()} to get keyless
     * signature.  Uses hash algorithm defined by method {@link KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param file
     *         file to sign. not null.
     * @return instance of {@link Future}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncSign(File file) throws KSIException;

    /**
     * This method is used to sign a byte array asynchronously. Use method {@link Future#getResult()} to get keyless
     * signature.  Uses hash algorithm defined by method {@link KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param bytes
     *         file to sign. not null.
     * @return instance of {@link Future}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncSign(byte[] bytes) throws KSIException;

    /**
     * Extends signature to the "closest" publication in publication file.
     *
     * @param signature
     *         signature to be extended. not null.
     * @return KSISignature extended keyless signature
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature extend(KSISignature signature) throws KSIException;

    /**
     * Extends the signature to specified publication record. The publication time of the publication record must be
     * after signature aggregation time. When signature is extended then the old calendar hash chain and publication
     * record is removed.
     *
     * @param signature
     *         signature to be extended. not null.
     * @param publicationRecord
     *         publication record to extend. not null.
     * @return extended keyless signature with extended calendar hash chain and publication record
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * Extends signature to the calendar head.
     *
     * @param signature
     *         signature to be extended. not null.
     * @return KSISignature extended keyless signature
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature extendToCalendarHead(KSISignature signature) throws KSIException;

    /**
     * This method is used to extend signature asynchronously to closes publication. Use method {@link
     * Future#getResult()} to get the extended keyless signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to extend. not null.
     * @return instance of {@link Future} future
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncExtend(KSISignature signature) throws KSIException;

    /**
     * This method is used to extend signature asynchronously to the given publication. Use method {@link
     * Future#getResult()} to get the extended keyless signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to extend. not null.
     * @param publicationRecord
     *         instance of {@link PublicationRecord} to extend the signature.
     * @return instance of {@link Future} future
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * This method is used to extend signature asynchronously to the newest publication found in publications file. Use
     * method {@link Future#getResult()} to get the extended keyless signature.
     *
     * @param signature
     *         instance of {@link KSISignature} to extend. not null.
     * @return instance of {@link Future} future
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncExtendToCalendarHead(KSISignature signature) throws KSIException;

    /**
     * This method is used to verify the keyless signature.
     *
     * @param context
     *         instance of {@link VerificationContext} to be used to validate the signature.
     * @param policy
     *         policy to be used to verify the signature.
     * @return returns the verification result
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    VerificationResult verify(VerificationContext context, Policy policy) throws KSIException;

    /**
     * Convenience method to verify KSI signature. Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy) throws KSIException;

    /**
     * Convenience method to verify KSI signature.Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param publicationData
     *         publication data to be used to verify signature. may be null.
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy, PublicationData publicationData) throws KSIException;

    /**
     * Convenience method to verify KSI signature.Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param documentHash
     *         the original document hash. may be null
     * @see KSI#verify(KSISignature, Policy, DataHash, PublicationData)
     */
    VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash) throws KSIException;

    /**
     * Convenience method to verify KSI signature.Uses the {@link com.guardtime.ksi.service.client.KSIExtenderClient}
     * defined by {@link KSIBuilder#setKsiProtocolExtenderClient(KSIExtenderClient)} method. The publications file is
     * downloaded using the client specified by method {@link KSIBuilder#setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient)}.
     *
     * @param signature
     *         signature to verify.
     * @param policy
     *         policy to be used to verify the signature.
     * @param documentHash
     *         the original document hash. may be null
     * @param publicationData
     *         publication data to be used to verify signature. may be null.
     * @see KSI#verify(VerificationContext, Policy)
     */
    VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash, PublicationData publicationData) throws KSIException;

    /**
     * This method is used to get the publications file. Uses the {@link com.guardtime.ksi.service.client.KSIPublicationsFileClient}
     * to download the publications file.
     *
     * @return instance of the {@link PublicationsFile}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    PublicationsFile getPublicationsFile() throws KSIException;

}
