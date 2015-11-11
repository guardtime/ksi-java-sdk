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

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.ChainResult;

/**
 * Aggregation hash chain hash calculation result
 */
final class InMemoryChainResult implements ChainResult {

    private final DataHash lastHash;
    private final long level;

    /**
     * Create hash chain result.
     *
     * @param lastHash
     *         last chain
     * @param level
     *         chain result level
     */
    public InMemoryChainResult(DataHash lastHash, long level) {
        this.lastHash = lastHash;
        this.level = level;
    }

    /**
     * @return level
     */
    public final long getLevel() {
        return level;
    }

    /**
     * @return output hash
     */
    public final DataHash getOutputHash() {
        return lastHash;
    }

    @Override
    public String toString() {
        return lastHash + ", level=" + level;
    }
}
