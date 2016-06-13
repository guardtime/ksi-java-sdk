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
package com.guardtime.ksi.service.extension;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.AbstractKSIRequest;
import com.guardtime.ksi.service.KSIMessageHeader;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;

/**
 * Outgoing extension message TLV object.
 */
public class ExtensionRequest extends AbstractKSIRequest<ExtensionRequestPayload> {

    public static final int ELEMENT_TYPE = 0x300;


    public ExtensionRequest(KSIMessageHeader header, ExtensionRequestPayload payload, byte[] loginKey) throws KSIException {
        super(header, payload, loginKey);

    }

    public ExtensionRequest(TLVElement element, byte[] loginKey) throws KSIException {
        super(element, loginKey);
        if (getRequestPayload() == null) {
            throw new KSIProtocolException("Invalid KSI request. Extension request payload is missing");
        }

    }

    @Override
    protected ExtensionRequestPayload readPayload(TLVElement element) throws KSIException {
        return new ExtensionRequestPayload(element);
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }


}
