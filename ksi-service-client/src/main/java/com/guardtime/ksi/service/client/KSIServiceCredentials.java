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
package com.guardtime.ksi.service.client;

import java.io.UnsupportedEncodingException;

/**
 * KSI service credentials for HMAC authentication.
 */
public class KSIServiceCredentials implements ServiceCredentials {

    /**
     * Login ID.
     */
    private String loginId;
    /**
     * Login key.
     */
    private byte[] loginKey;

    /**
     * Create service credentials.
     *
     * String values will be converted to bytes using UTF-8 encoding, if this is
     * not desired, use other constructor.
     *
     * @param loginId
     *            login ID
     * @param loginKey
     *            login Key
     */
    public KSIServiceCredentials(String loginId, String loginKey) {
        this(loginId, toBytes(loginKey));
    }

    /**
     *
     * Create service credentials.
     *
     * @param loginId
     *            login ID
     * @param loginKey
     *            login Key
     */
    public KSIServiceCredentials(String loginId, byte[] loginKey) {
        if (loginId == null) {
            throw new IllegalArgumentException("loginId is null");
        }

        if (loginKey == null) {
            throw new IllegalArgumentException("loginKey is null");
        }
        this.loginId = loginId;
        this.loginKey = loginKey;
    }

    /**
     * @return returns login id
     */
    public String getLoginId() {
        return loginId;
    }

    /**
     * @return returns login key
     */
    public byte[] getLoginKey() {
        return loginKey;
    }

    private static byte[] toBytes(String loginKey) {
        try {
            if (loginKey == null) {
                throw new IllegalArgumentException("loginKey is null");
            }

            return loginKey.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Encoding loginKey failed", e);
        }
    }
}
