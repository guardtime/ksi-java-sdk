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

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;

/**
 * A signer class to create block signatures. Methods {@link BlockSigner#add(DataHash, long, IdentityMetadata)}, {@link
 * BlockSigner#add(DataHash, long, IdentityMetadata)} and/or {@link BlockSigner#add(DataHash)} can be used to add new
 * input hash to the block signer. Method {@link BlockSigner#sign()} must be called to get the final signatures.
 *
 *  @param <T>
 *         type of the created block signature
 */
public interface BlockSigner<T> {

    /**
     * Adds a new hash to the signer
     */
    KsiBlockSigner add(DataHash dataHash) throws KSIException;

    /**
     * Adds a new hash to the signer
     */
    KsiBlockSigner add(DataHash dataHash, IdentityMetadata metadata) throws KSIException;

    /**
     * Adds a new hash to the signer
     */
    KsiBlockSigner add(DataHash dataHash, long level, IdentityMetadata metadata) throws KSIException;

    /**
     * Check, if given hash could be added to the signer without exceeding given tree height
     *
     * @return if adding given hash does/does not exceed given tree height
     */
    boolean checkAdd(DataHash dataHash, long level, IdentityMetadata metadata, long maxTreeHeight) throws KSIException;

    /**
     * Creates a block signature
     */
    T sign() throws KSIException;

}
