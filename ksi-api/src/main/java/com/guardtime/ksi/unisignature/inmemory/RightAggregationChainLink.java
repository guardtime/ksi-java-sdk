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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.ChainResult;

/**
 * Right link implementation.
 *
 * @see InMemoryAggregationChainLink
 */
class RightAggregationChainLink extends InMemoryAggregationChainLink {

    public static final int ELEMENT_TYPE_RIGHT_LINK = 0x08;

    RightAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        super(siblingHash, levelCorrection);
    }


    RightAggregationChainLink(TLVElement element) throws KSIException {
        super(element);
    }

    /**
     * Calculates right link hash chain step.
     *
     * @param lastStepImprint
     *         imprint computed in the last step of the previous hash chain component
     * @param length
     *         length computed at the previous step or 0 if first step
     * @param algorithm
     *         hash algorithm to be used.
     * @return right link chain step calculation result.
     */
    @Override
    public ChainResult calculateChainStep(byte[] lastStepImprint, long length, HashAlgorithm algorithm) throws KSIException {
        long level = length + getLevelCorrection() + 1;
        DataHash hash = hash(getSiblingData(), lastStepImprint, level, algorithm);
        return new InMemoryChainResult(hash, level);
    }

    public boolean isLeft() {
        return false;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_RIGHT_LINK;
    }
}
