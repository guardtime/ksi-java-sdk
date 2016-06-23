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

import com.guardtime.ksi.util.Util;

/**
 * Metadata to be added to the signature.
 */
public class IdentityMetadata {

    private String clientId;
    private String machineId;
    private Long sequenceNumber;
    private Long requestTime;

    public IdentityMetadata(String clientId) {
        this(clientId, null, null, null);
    }

    public IdentityMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) {
        Util.notNull(clientId, "Client Identifier");
        this.clientId = clientId;
        this.machineId = machineId;
        this.sequenceNumber = sequenceNumber;
        this.requestTime = requestTime;
    }

    /**
     * Returns the client id to be added to the signature.
     * Mandatory metadata element
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns the machine id to be added to the signature.
     * Optional metadata element
     */
    public String getMachineId() {
        return machineId;
    }

    /**
     * Returns the sequence number to be added to the signature.
     * Optional metadata element
     */
    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Returns the request time to be added to the signature.
     * Optional metadata element
     */
    public Long getRequestTime() {
        return requestTime;
    }
}
