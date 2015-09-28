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
package com.guardtime.ksi.service.extension;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.AbstractKSIRequest;
import com.guardtime.ksi.service.KSIMessageHeader;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVHeader;

import java.util.List;

/**
 * Outgoing extension message TLV object.
 */
public class ExtensionRequest extends AbstractKSIRequest {

    public static final int ELEMENT_TYPE = 0x300;
    private static final int ELEMENT_TYPE_MAC = 0x1F;

    private KSIMessageHeader header;
    private ExtensionRequestPayload payload;
    private DataHash mac;

    public ExtensionRequest(ExtensionRequestPayload payload, KSIRequestContext context) throws KSIException {
        super(context);
        this.context = context;
        this.header = new KSIMessageHeader(context.getLoginId());
        this.payload = payload;

        this.rootElement = new TLVElement(new TLVHeader(false, false, ELEMENT_TYPE));
        this.rootElement.addChildElement(header.getRootElement());

        if (payload != null) {
            this.rootElement.addChildElement(payload.getRootElement());
        }
        this.mac = calculateMac();

        TLVElement macElement = new TLVElement(new TLVHeader(false, false, ELEMENT_TYPE_MAC));
        macElement.setDataHashContent(mac);
        this.rootElement.addChildElement(macElement);
    }

    public ExtensionRequest(TLVElement element, KSIRequestContext context) throws KSIException {
        super(element, context);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case KSIMessageHeader.ELEMENT_TYPE_MESSAGE_HEADER:
                    this.header = new KSIMessageHeader(readOnce(child));
                    continue;
                case ExtensionRequestPayload.ELEMENT_TYPE_EXTENSION_REQUEST_PAYLOAD:
                    this.payload = new ExtensionRequestPayload(readOnce(child));
                    continue;
                case ELEMENT_TYPE_MAC:
                    this.mac = readOnce(child).getDecodedDataHash();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (header == null) {
            throw new KSIProtocolException("Invalid KSI request. Extension request header is missing");
        }
        if (payload == null) {
            throw new KSIProtocolException("Invalid KSI request. Extension request payload is missing");
        }
        if (mac == null) {
            throw new KSIProtocolException("Invalid KSI request. Extension request mac is missing");
        }
    }

    /**
     * Get the header of message.
     *
     * @return header for the message
     */
    public KSIMessageHeader getHeader() {
        return this.header;
    }

    public ExtensionRequestPayload getRequestPayload() {
        return payload;
    }

    /**
     * @return outgoing extension message hmac
     */
    public DataHash getMac() {
        return mac;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }
}
