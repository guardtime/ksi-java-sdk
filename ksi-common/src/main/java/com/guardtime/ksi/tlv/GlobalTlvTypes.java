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

public final class GlobalTlvTypes {

    private GlobalTlvTypes(){
    }

    // signature tlv types
    public static final int ELEMENT_TYPE_SIGNATURE = 0x0800;
    public static final int ELEMENT_TYPE_AGGREGATION_HASH_CHAIN = 0x0801;
    public static final int ELEMENT_TYPE_CALENDAR_HASH_CHAIN = 0x0802;
    public static final int ELEMENT_TYPE_SIGNATURE_PUBLICATION_RECORD = 0x0803;
    public static final int ELEMENT_TYPE_AGGREGATION_AUTHENTICATION_RECORD = 0x0804;
    public static final int ELEMENT_TYPE_CALENDAR_AUTHENTICATION_RECORD = 0x0805;
    public static final int ELEMENT_TYPE_RFC_3161_RECORD = 0x0806;

    // PDU types
    public static final int ELEMENT_TYPE_AGGREGATION_PDU_V1 = 0x0200;
    public static final int ELEMENT_TYPE_EXTENSION_PDU_V1 = 0x0300;
    public static final int ELEMENT_TYPE_AGGREGATION_REQUEST_PDU_V2 = 0x0220;
    public static final int ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2 = 0x0221;
    public static final int ELEMENT_TYPE_EXTENSION_REQUEST_PDU_V2 = 0x0320;
    public static final int ELEMENT_TYPE_EXTENSION_RESPONSE_PDU_V2 = 0x0321;

}
