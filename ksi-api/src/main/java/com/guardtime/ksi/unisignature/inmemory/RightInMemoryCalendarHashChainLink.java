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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;

/**
 * Right calendar hash chain link.
 *
 * @see InMemoryCalendarHashChainLink
 */
class RightInMemoryCalendarHashChainLink extends InMemoryCalendarHashChainLink {

    public static final int ELEMENT_TYPE = 0x08;

    RightInMemoryCalendarHashChainLink(TLVElement rootElement) throws KSIException {
        super(rootElement);
    }

    @Override
    public final DataHash calculateChainStep(DataHash previous) throws InvalidCalendarHashChainException {
        return calculateStep(dataHash.getImprint(), previous.getImprint(), previous.getAlgorithm());
    }

    @Override
    public boolean isRightLink() {
        return true;
    }

    @Override
    public final int getElementType() {
        return ELEMENT_TYPE;
    }

}
