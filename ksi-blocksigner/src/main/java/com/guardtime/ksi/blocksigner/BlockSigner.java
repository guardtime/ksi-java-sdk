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

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;

/**
 * Provides the means to create multiple signatures with one signing request.
 * <p>
 * Methods {@link BlockSigner#add(DataHash, long, IdentityMetadata)},
 * {@link BlockSigner#add(DataHash, long, IdentityMetadata)} and/or {@link BlockSigner#add(DataHash)}
 * can be used to add new input hash to the block signer. Method {@link BlockSigner#sign()} must be
 * called to get the final signatures.
 *</p>
 *  @param <T>
 *         type of the created signatures.
 */
public interface BlockSigner<T> {

    /**
     * Adds a new hash to the signer.
     *
     * @param dataHash data hash to be added.
     *
     * @return True, if the hash was added as a result of the call.
     * If adding given hash exceeds the allowed tree height, no hash is added to signer.
     *
     * @throws KSIException
     */
    boolean add(DataHash dataHash) throws KSIException;

    /**
     * Adds a new hash and metadata to the signer.
     *
     * @param dataHash data to be added.
     * @param metadata metadata to be added.
     *
     * @return True, if the hash and metadata were added as a result of the call.
     * If adding given hash and metadata exceeds the allowed tree height, no hash and no metadata is added to signer.
     *
     * @throws KSIException
     */
    boolean add(DataHash dataHash, IdentityMetadata metadata) throws KSIException;

    /**
     * Adds a new hash, level, and metadata to the signer.
     *
     * @param dataHash data hash to be added.
     * @param level level to be added.
     * @param metadata metadata to be added.
     *
     * @return True, if the hash, level, and metadata were added as a result of the call.
     * If adding given hash and metadata exceeds the allowed tree height, non of the parameters is added to signer.
     *
     * @throws KSIException
     */
    boolean add(DataHash dataHash, long level, IdentityMetadata metadata) throws KSIException;

    /**
     * Creates a block of multiple signatures.
     * All of the block signer inputs are locally aggregated and aggregation root is signed in GW.
     * For each signer input a signature is created from root signature, and also a hash tree for specific input from locally aggregated hash tree.
     *
     * @return The block of multiple signatures.
     *
     * @throws KSIException
     */
    T sign() throws KSIException;

}
