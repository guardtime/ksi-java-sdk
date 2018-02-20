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
package com.guardtime.ksi.util;

/**
 * <a target="_blank" href="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</a>
 * base-64 encoding/decoding.
 */
public final class Base64 {

    /**
     * The encoder/decoder instance.
     */
    private static BaseX inst = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true, '=');

    /**
     * Encodes the given bytes into a base-64 string.
     *
     * @param in
     *            the bytes to encode.
     *
     * @return The base-64 string, or null if {@code in} is null.
     */
    public static String encode(byte[] in) {
        if (in == null) {
            return null;
        }
        return encode(in, 0, in.length);
    }

    /**
     * Encodes the given bytes into a base-64 string.
     *
     * @param in
     *            an array containing the bytes to encode.
     * @param off
     *            the start offset of the data within {@code in}.
     * @param len
     *            the number of bytes to encode.
     *
     * @return The base-64 string.
     */
    public static String encode(byte[] in, int off, int len) {
        return inst.encode(in, off, len, null, 0).toString();
    }

    /**
     * Decodes the given base-64 string into bytes. Any non-base-64 characters
     * are silently ignored.
     *
     * @param in
     *            the base-64 string to decode.
     *
     * @return The decoded bytes, or null if {@code in} is null.
     */
    public static byte[] decode(String in) {
        if (in == null) {
            return null;
        }
        return inst.decode(in);
    }

    /**
     * Should not be instantiated.
     */
    private Base64() {
    }

}
