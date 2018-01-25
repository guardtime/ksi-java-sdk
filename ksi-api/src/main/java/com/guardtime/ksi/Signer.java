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
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.unisignature.KSISignature;

import java.io.Closeable;
import java.io.File;

/**
 * Signing data or data hash, synchronously or asynchronously. An instance of this class can be obtained using {@link SignerBuilder} class.
 */
public interface Signer extends Closeable {

    /**
     * Signs the data hash.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign, not null.
     * @return KSI signature ({@link KSISignature}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    KSISignature sign(DataHash dataHash) throws KSIException;

    /**
     * Signs the data hash with user provided aggregation tree height.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign. not null.
     * @param level
     *         aggregation tree height.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature sign(DataHash dataHash, long level) throws KSIException;

    /**
     * Signs the file. Uses hash algorithm defined by method {@link
     * KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param file
     *         file to sign, not null.
     * @return KSI signature ({@link KSISignature}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    KSISignature sign(File file) throws KSIException;

    /**
     * Signs the byte array. Uses hash algorithm defined by method {@link
     * KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     *
     * @param bytes
     *         bytes to sign, not null.
     * @return KSI signature ({@link KSISignature}).
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    KSISignature sign(byte[] bytes) throws KSIException;

    /**
     * Signs the data hash asynchronously. Use method {@link Future#getResult()} to get the KSI
     * signature.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign, not null.
     * @return Instance of {@link Future}.
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    Future<KSISignature> asyncSign(DataHash dataHash) throws KSIException;

    /**
     * This method is used to sign data hash asynchronously with user provided aggregation tree height.
     * Use method {@link Future#getResult()} to get keyless signature.
     *
     * @param dataHash
     *         instance of {@link DataHash} to sign. not null.
     * @param level
     *         aggregation tree height.
     * @return instance of {@link Future}
     * @throws KSIException
     *         when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncSign(DataHash dataHash, long level) throws KSIException;

    /**
     * Signs the file asynchronously. Uses hash algorithm defined by method
     * {@link KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     * Use method {@link Future#getResult()} to get the KSI signature.
     *
     * @param file
     *         file to sign, not null.
     * @return Instance of {@link Future}.
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    Future<KSISignature> asyncSign(File file) throws KSIException;

    /**
     * Signs the byte array asynchronously. Uses hash algorithm defined by method
     * {@link KSIBuilder#setDefaultSigningHashAlgorithm(HashAlgorithm)}.
     * Use method {@link Future#getResult()} to get the KSI signature.
     *
     * @param bytes
     *         file to sign, not null.
     * @return Instance of {@link Future}
     * @throws KSIException
     *         when error occurs (e.g. when communication with KSI service fails).
     */
    Future<KSISignature> asyncSign(byte[] bytes) throws KSIException;

    /**
     * Gets the signing service that the SDK was initialized with.
     * E.g. to get access to signing service's configuration.
     */
    KSISigningService getSigningService();

    /**
     * Asks aggregation configuration from KSI gateway/aggregator. Only supported
     * if {@link com.guardtime.ksi.pdu.PduVersion#V2} is used.
     *
     * @deprecated Deprecated since 4.10. Use {@link KSISigningService#getAggregationConfiguration()}
     *      in pair with {@link KSISigningService#registerAggregatorConfigurationListener(ConfigurationListener)} instead.
     *      To acquire instance of {@link KSISigningService} which a {@link KSI} instance uses, call
     *      {@link KSI#getSigningService()}.
     *
     * @throws UnsupportedOperationException if KSI is initialized with a service not a client.
     */
    @Deprecated
    AggregatorConfiguration getAggregatorConfiguration() throws KSIException;
}
