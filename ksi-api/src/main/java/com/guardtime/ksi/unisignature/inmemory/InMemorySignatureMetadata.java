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

import com.guardtime.ksi.unisignature.SignatureMetadata;
import com.guardtime.ksi.util.Util;

public class InMemorySignatureMetadata implements SignatureMetadata {

    private final String clientId;
    private String machineId;
    private long sequenceNumber;
    private long requestTime;
    private byte[] padding;

    public InMemorySignatureMetadata(String clientId) {
        this(clientId, null, null, null, new byte[0]);
    }

    public InMemorySignatureMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime, byte[] paddingBytes) {
        Util.notNull(clientId, "Client Identifier");
        this.clientId = clientId;
        if (machineId != null) this.machineId = machineId;
        if (sequenceNumber != null) this.sequenceNumber = sequenceNumber;
        if (requestTime != null) this.requestTime = requestTime;
        this.padding = paddingBytes;
    }

    public String getClientId() {
        return clientId;
    }

    public String getMachineId() {
        return machineId;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public Long getRequestTime() {
        return requestTime;
    }

    public byte[] getPadding() {
        return padding;
    }
}
