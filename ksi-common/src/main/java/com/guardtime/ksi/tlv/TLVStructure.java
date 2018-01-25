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

package com.guardtime.ksi.tlv;

import com.guardtime.ksi.exceptions.KSIException;

import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

public abstract class TLVStructure {

    protected TLVElement rootElement;
    private Set<Integer> processedElements = new HashSet<>();

    /**
     * Constructor for decoding TLV element.
     *
     * @param rootElement
     *         inmemory element to decode, not null.
     *
     * @throws TLVParserException
     *         when root element is null or root element type does not match
     *         with inmemory structure type.
     */
    public TLVStructure(TLVElement rootElement) throws TLVParserException {
        if (rootElement == null) {
            throw new TLVParserException("Root element must be present");
        }
        if (getElementType() != rootElement.getType()) {
            throw new TLVParserException("Invalid TLV element. Expected=0x" + Integer.toHexString(getElementType()) + ", got=0x"
                    + Integer.toHexString(rootElement.getType()));
        }
        this.rootElement = rootElement;
    }

    /**
     * Constructors to be used to create new inmemory structure element.
     */
    public TLVStructure() {
    }

    /**
     * Checks if the TLV element is critical or not.
     *
     * @param element
     *         TLV element to check.
     *
     * @throws TLVParserException
     *         when unknown critical TLV element is encountered.
     */
    protected void verifyCriticalFlag(TLVElement element) throws TLVParserException {
        if (!element.isNonCritical()) {
            throw new TLVParserException("Unknown critical TLV element with tag=0x" + Integer.toHexString(element.getType()) + " encountered");
        }
    }

    /**
     * @param element
     *         TLV element of type to read only once.
     *
     * @return Instance of {@link TLVElement}.
     *
     * @throws TLVParserException
     *         when TLV element of given type is already processed.
     */
    protected TLVElement readOnce(TLVElement element) throws TLVParserException {
        int tlvElementType = element.getType();
        if (!processedElements.contains(tlvElementType)) {
            processedElements.add(tlvElementType);
            return element;
        }
        throw new TLVParserException("Multiple TLV 0x" + Integer.toHexString(tlvElementType) + " elements. Only one is allowed.");
    }

    public abstract int getElementType();

    public void writeTo(OutputStream out) throws KSIException {
        if(out == null) {
            throw new KSIException("Output stream can not be null");
        }
        rootElement.writeTo(out);
    }

    public TLVElement getRootElement() {
        return rootElement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TLVStructure that = (TLVStructure) o;
        return !(rootElement != null ? !rootElement.equals(that.rootElement) : that.rootElement != null);
    }

    @Override
    public int hashCode() {
        return rootElement != null ? rootElement.hashCode() : 0;
    }
}
