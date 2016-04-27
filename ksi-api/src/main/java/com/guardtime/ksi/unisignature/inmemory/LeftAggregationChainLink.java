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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.ChainResult;

/**
 * Left link implementation.
 *
 * @see InMemoryAggregationChainLink
 */
class LeftAggregationChainLink extends InMemoryAggregationChainLink {

    public static final int ELEMENT_TYPE_LEFT_LINK = 0x07;

    LeftAggregationChainLink(DataHash siblingHash, long levelCorrection) throws KSIException {
        super(siblingHash, levelCorrection);
    }

    LeftAggregationChainLink(String clientId, long levelCorrection) throws KSIException {
        super(clientId, levelCorrection);
    }

    LeftAggregationChainLink(TLVElement element) throws KSIException {
        super(element);
    }

    @Override
    public ChainResult calculateChainStep(byte[] lastStepImprint, long length, HashAlgorithm algorithm) throws KSIException {
        long level = length + getLevelCorrection() + 1;
        DataHash hash = hash(lastStepImprint, getSiblingData(), level, algorithm);
        return new InMemoryChainResult(hash, level);
    }

    public boolean isLeft() {
        return true;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_LEFT_LINK;
    }

}
