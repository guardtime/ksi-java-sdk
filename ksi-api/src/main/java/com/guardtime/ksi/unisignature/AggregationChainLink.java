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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureException;

/**
 * AggregationChainLink structure contains the following information: <ul> <li>May contain level correction value.
 * Default value is 0</li> <li>One and only one of the following three fields</li> <ul> <li>sibling hash - an `imprint'
 * representing a hash value from the sibling node in the tree</li> <li>metadata - a sub-structure that provides the
 * ability to incorporate client identity and other information about the request into the hash chain.</li> <li>metadata
 * hash - metadata of limited length encoded as an imprint. This option is present for backwards compatibility with
 * existing signatures created before the structured `metadata' field was introduced.</li> </ul>
 * <p/>
 * </ul>
 */
public interface AggregationChainLink {

    ChainResult calculateChainStep(byte[] lastStepImprint, long length, HashAlgorithm algorithm) throws KSIException;

    /**
     * @deprecated use {@link AggregationChainLink#getLinkIdentity()} instead
     */
    @Deprecated
    String getIdentity() throws InvalidSignatureException;

    Identity getLinkIdentity();

    boolean isLeft();

    LinkMetadata getMetadata();

    byte[] getSiblingData() throws KSIException;
}
