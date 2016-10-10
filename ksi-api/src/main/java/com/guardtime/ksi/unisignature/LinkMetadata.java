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

import com.guardtime.ksi.tlv.TLVStructure;

/**
 * Wrapper interface that provides access to {@link IdentityMetadata} and its raw {@link TLVStructure} that is contained
 * in the {@link AggregationChainLink}.
 */
public interface LinkMetadata {

    /**
     * Provides access to {@link IdentityMetadata} contained in {@link AggregationChainLink}.
     *
     * @return Instance of {@link IdentityMetadata}.
     */
    IdentityMetadata getIdentityMetadata();

    /**
     * Provides access to {@link TLVStructure} which contains raw data for {@link IdentityMetadata} as well as any extra
     * components specified by RFC.
     *
     * @return {@link TLVStructure} as described by RFC.
     */
    TLVStructure getMetadataStructure();
}