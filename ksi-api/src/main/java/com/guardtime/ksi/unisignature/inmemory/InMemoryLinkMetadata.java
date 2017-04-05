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
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.IdentityType;
import com.guardtime.ksi.unisignature.LinkMetadata;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;

class InMemoryLinkMetadata extends TLVStructure implements LinkMetadata, Identity {

    public static final int ELEMENT_TYPE_METADATA = 0x04;

    public static final int ELEMENT_TYPE_CLIENT_ID = 0x01;
    public static final int ELEMENT_TYPE_MACHINE_ID = 0x02;
    public static final int ELEMENT_TYPE_SEQUENCE_NUMBER = 0x03;
    public static final int ELEMENT_TYPE_REQUEST_TIME = 0x04;
    public static final int ELEMENT_TYPE_PADDING = 0x1E;

    private String clientId;
    private String machineId;
    private Long sequenceNumber;
    private Long requestTime;
    private IdentityType identityType = IdentityType.METADATA;

    public InMemoryLinkMetadata(String clientId) throws KSIException {
        this(clientId, null, null, null);
    }

    public InMemoryLinkMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) throws KSIException {
        this.clientId = clientId;
        this.machineId = machineId;
        this.sequenceNumber = sequenceNumber;
        this.requestTime = requestTime;
        this.rootElement = new TLVElement(false, false, getElementType());
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_CLIENT_ID, clientId));
        if (machineId != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_MACHINE_ID, machineId));
        }
        if (sequenceNumber != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_SEQUENCE_NUMBER, sequenceNumber));
        }
        if (requestTime != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_TIME, requestTime));
        }
        this.identityType = IdentityType.PADDED_METADATA;
        this.rootElement.addFirstChildElement(createPaddingTlvElement());
    }

    public InMemoryLinkMetadata(TLVElement tlvElement) throws KSIException {
        super(tlvElement);
        List<TLVElement> children = tlvElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_CLIENT_ID:
                    clientId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_MACHINE_ID:
                    machineId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_SEQUENCE_NUMBER:
                    sequenceNumber = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_REQUEST_TIME:
                    requestTime = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_PADDING:
                    identityType = IdentityType.PADDED_METADATA;
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (clientId == null) {
            throw new InvalidAggregationHashChainException("AggregationChainLink metadata does not contain clientId element");
        }
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_METADATA;
    }

    private TLVElement createPaddingTlvElement() throws TLVParserException {
        TLVElement element = new TLVElement(true, true, ELEMENT_TYPE_PADDING);
        int padding = 1;
        if (this.rootElement.getContentLength() % 2 == 0) {
            padding = 2;
        }
        byte[] bytes = new byte[padding];
        Arrays.fill(bytes, (byte) 0x01);
        element.setContent(bytes);
        return element;
    }

    public TLVStructure getMetadataStructure() {
        return this;
    }

    public IdentityType getType() {
        return identityType;
    }

    public byte[] getClientId() throws UnsupportedEncodingException {
        if (clientId != null) {
            return clientId.getBytes("UTF-8");
        }
        return null;
    }

    public String getDecodedClientId() {
        return clientId;
    }

    public byte[] getMachineId() throws UnsupportedEncodingException {
        if (machineId != null) {
            return machineId.getBytes("UTF-8");
        }
        return null;
    }

    public String getDecodedMachineId() {
        return machineId;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public Long getRequestTime() {
        return requestTime;
    }
}
