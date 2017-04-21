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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;

class ExtensionResponsePduV2 extends PduV2 {

    private static final int[] SUPPORTED_PAYLOAD_TYPES = new int[]{0x02, 0x03, 0x04};

    public ExtensionResponsePduV2(TLVElement rootElement, byte[] loginKey) throws KSIException {
        super(rootElement, loginKey);
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return SUPPORTED_PAYLOAD_TYPES;
    }

    @Override
    public int getElementType() {
        return GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_RESPONSE_PDU_V2;
    }

}
