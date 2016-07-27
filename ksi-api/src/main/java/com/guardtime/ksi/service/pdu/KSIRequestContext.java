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
package com.guardtime.ksi.service.pdu;

import com.guardtime.ksi.service.client.ServiceCredentials;


/**
 * Helper class for KSI request/response. This class holds additional data that
 * specific data like request identifier and login key.
 * can be used when sending request and parsing responses.
 */
public final class KSIRequestContext {

    private Long requestId;
    private Long instanceId;
    private Long messageId;
    private ServiceCredentials credentials;

    /**
     * @param credentials instance of {@link ServiceCredentials} object
     * @param requestId   - request id
     */
    public KSIRequestContext(ServiceCredentials credentials, Long requestId) {
        this.credentials = credentials;
        this.requestId = requestId;
    }

    public KSIRequestContext(ServiceCredentials credentials, Long requestId, Long instanceId, Long messageId) {
        this.requestId = requestId;
        this.instanceId = instanceId;
        this.messageId = messageId;
        this.credentials = credentials;
    }

    public Long getRequestId() {
        return requestId;
    }

    public String getLoginId() {
        return credentials.getLoginId();
    }

    public byte[] getLoginKey() {
        return credentials.getLoginKey();
    }

    public Long getInstanceId() {
        return instanceId;
    }

    public Long getMessageId() {
        return messageId;
    }
}
