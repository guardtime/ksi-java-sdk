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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.extension.ExtensionResponsePayload;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

/**
 * Common abstract class for all KSI related response payloads.
 *
 * @see ExtensionResponsePayload
 */
public abstract class KSIResponsePayload extends TLVStructure {

    /**
     * Constructor used to parse response payload.
     *
     * @param element instance of {@link TLVElement} to createSignature
     */
    public KSIResponsePayload(TLVElement element) throws KSIException {
        super(element);
    }

    /**
     * @return returns request id
     */
    public abstract Long getRequestId();

    /**
     * @return returns error code
     */
    public abstract Long getError();

    /**
     * @return returns error message
     */
    public abstract String getErrorMessage();

}
