/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;

import java.util.List;

class ExtensionRequestPduV2 extends PduV2 implements ExtensionRequest {

    private static final int[] SUPPORTED_PAYLOAD_TYPES = new int[]{0x02, 0x04};

    public ExtensionRequestPduV2(List<TLVElement> payloads, HashAlgorithm macAlgorithm, KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        super(new PduMessageHeader(credentials.getLoginId(), context), payloads, macAlgorithm, credentials.getLoginKey());
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return SUPPORTED_PAYLOAD_TYPES;
    }

    @Override
    public int getElementType() {
        return GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_REQUEST_PDU_V2;
    }

    public byte[] toByteArray() {
        try {
            return getRootElement().getEncoded();
        } catch (TLVParserException e) {
            throw new IllegalArgumentException("Invalid aggregation request state");
        }
    }
}
