/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.client;

import com.guardtime.ksi.hashing.HashAlgorithm;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

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

    private HashAlgorithm hmacAlgorithm = HashAlgorithm.SHA2_256;

    /**
     * Creates service credentials. Default HMAC algorithm (SHA-256) will be used.
     *
     * Parameter loginKey will be converted to bytes using UTF-8 encoding, if this is
     * not desired, use other constructor.
     *
     * @param loginId
     *            login ID.
     * @param loginKey
     *            login key.
     */
    public KSIServiceCredentials(String loginId, String loginKey) {
        this(loginId, toBytes(loginKey), null);
    }

    /**
     * Creates service credentials. Default HMAC algorithm (SHA-256) will be used.
     *
     * Parameter loginKey will be converted to bytes using UTF-8 encoding, if this is
     * not desired, use other constructor.
     *
     * @param loginId
     *            login ID.
     * @param loginKey
     *            login key.
     * @param hmacAlgorithm
     *            HMAC algorithm of incoming messages.
     */
    public KSIServiceCredentials(String loginId, String loginKey, HashAlgorithm hmacAlgorithm) {
        this(loginId, toBytes(loginKey), hmacAlgorithm);
    }

    /**
    *
    * Creates service credentials. Default HMAC algorithm (SHA-256) will be used.
    *
    * @param loginId
    *            login ID.
    * @param loginKey
    *            login key.
    */
    public KSIServiceCredentials(String loginId, byte[] loginKey) {
        this(loginId, loginKey, null);
    }

    /**
     *
     * Creates service credentials.
     *
     * @param loginId
     *            login ID.
     * @param loginKey
     *            login key.
     * @param hmacAlgorithm
     *            HMAC algorithm of incoming messages.
     */
    public KSIServiceCredentials(String loginId, byte[] loginKey, HashAlgorithm hmacAlgorithm) {
        if (loginId == null) {
            throw new IllegalArgumentException("loginId is null");
        }
        if (loginKey == null) {
            throw new IllegalArgumentException("loginKey is null");
        }
        if (hmacAlgorithm != null) {
            hmacAlgorithm.checkExpiration();
            this.hmacAlgorithm = hmacAlgorithm;
        }
        this.loginId = loginId;
        this.loginKey = loginKey;
    }

    /**
     * @return Login ID.
     */
    public String getLoginId() {
        return loginId;
    }

    /**
     * @return Login key.
     */
    public byte[] getLoginKey() {
        return loginKey;
    }

    /**
     * @return Verification algorithm for the HMAC of incoming messages.
     */
    public HashAlgorithm getHmacAlgorithm() {
        return hmacAlgorithm;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        KSIServiceCredentials that = (KSIServiceCredentials) o;

        if (loginId != null ? !loginId.equals(that.loginId) : that.loginId != null) return false;
        return Arrays.equals(loginKey, that.loginKey);
    }
}
