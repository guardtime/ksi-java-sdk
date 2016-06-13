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

/**
 * Common exception related to KSI protocol.
 */
public class KSIProtocolException extends KSIException {

    private static final long serialVersionUID = 1683153671580933615L;
    private Long errorCode;

    /**
     * Create service exception.
     *
     * @param eCode
     *         error code
     * @param msg
     *         error message
     */
    public KSIProtocolException(Long eCode, String msg) {
        this(eCode, msg, null);
    }

    /**
     * Create service exception.
     *
     * @param eCode
     *         error code
     * @param msg
     *         error message
     * @param cause
     *         error cause
     */
    public KSIProtocolException(Long eCode, String msg, Throwable cause) {
        super("(" + eCode + "):" + msg, cause);
        this.errorCode = eCode;
    }

    /**
     * Create service exception
     *
     * @param message
     *         error message
     */
    public KSIProtocolException(String message) {
        super(message);
    }

    /**
     * Create service exception
     *
     * @param message
     *         error message
     * @param cause
     *         error cause
     */
    public KSIProtocolException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     *
     * @return returns error code is present.
     */
    public long getErrorCode() {
        return errorCode;
    }

}
