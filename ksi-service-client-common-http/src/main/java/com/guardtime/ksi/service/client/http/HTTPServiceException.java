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
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.service.client.KSIClientException;

/**
 * HTTP ServiceException class.
 */
public class HTTPServiceException extends KSIClientException {

    private static final long serialVersionUID = -1173038305861702243L;
    private final int errorCode;

    /**
     * Create HTTP service exception.
     *
     * @param errorCode
     *         error code
     * @param msg
     *         error message
     */
    public HTTPServiceException(int errorCode, String msg) {
        super("(" + errorCode + "):" + msg);
        this.errorCode = errorCode;
    }


    public int getErrorCode() {
        return errorCode;
    }
}
