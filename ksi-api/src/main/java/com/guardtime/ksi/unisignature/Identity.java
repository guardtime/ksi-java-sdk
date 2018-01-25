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

package com.guardtime.ksi.unisignature;

import java.io.UnsupportedEncodingException;

/**
 * A structure that contains client identity and other information about the aggregation hash chain.
 */
public interface Identity {

    /**
     * Returns the type of the identity.
     */
    IdentityType getType();

    /**
     * Returns a byte array of the client id.
     */
    byte[] getClientId() throws UnsupportedEncodingException;

    /**
     * Returns a human-readable textual representation of client identity;
     */
    String getDecodedClientId();

    /**
     * Returns a identifier of the machine id. May be null.
     */
    byte[] getMachineId() throws UnsupportedEncodingException;

    /**
     * Returns a human-readable textual representation of machine identity. May be null.
     */
    String getDecodedMachineId();

    /**
     * Returns a local sequence number of a request assigned by the machine that created the aggregation link. May be null.
     */
    Long getSequenceNumber();

    /**
     * Returns the time when the server received the request from the client. May be null.
     */
    Long getRequestTime();

}
