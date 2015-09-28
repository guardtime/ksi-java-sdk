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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Contains the common logic for all KSI related request messages.
 */
public abstract class AbstractKSIRequest extends TLVStructure {

    protected KSIRequestContext context;

    /**
     * Used to createSignature new instances of request objects.
     *
     * @param context
     *         - instance of {@link KSIRequestContext}
     */
    public AbstractKSIRequest(KSIRequestContext context) {
        this.context = context;
    }

    /**
     * Used to parse request objects.
     *
     * @param element
     *         - instance of {@link TLVElement} to createSignature
     * @param context
     *         - instance of {@link KSIRequestContext}
     */
    public AbstractKSIRequest(TLVElement element, KSIRequestContext context) throws KSIException {
        super(element);
        this.context = context;
    }

    /**
     * @return returns instance of {@link KSIMessageHeader}.
     */
    public abstract KSIMessageHeader getHeader();

    /**
     * @return returns instance of request payload.
     */
    public abstract TLVStructure getRequestPayload();

    /**
     * Calculates the MAC based on header and payload TLVs.
     *
     * @return calculated data hash
     * @throws KSIException
     *         if hmac generation fails
     */
    protected DataHash calculateMac() throws KSIException {
        try {
            HashAlgorithm algorithm = HashAlgorithm.getByName("DEFAULT");
            return new DataHash(algorithm, Util.calculateHMAC(getContent(), this.context.getLoginKey(), algorithm.getName()));
        } catch (IOException e) {
            throw new KSIProtocolException("Problem with HMAC", e);
        } catch (InvalidKeyException e) {
            throw new KSIProtocolException("Problem with HMAC key.", e);
        } catch (NoSuchAlgorithmException e) {
            // If the default algorithm changes to be outside of MD5 / SHA1 /
            // SHA256 list.
            throw new KSIProtocolException("Unsupported HMAC algorithm.", e);
        } catch (HashException e) {
            throw new KSIProtocolException(e.getMessage(), e);
        }
    }

    private byte[] getContent() throws IOException, KSIException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        getHeader().writeTo(out);
        TLVStructure payload = getRequestPayload();
        if (payload != null) {
            payload.writeTo(out);
        } else {
            out.write(Util.toByteArray(0));
        }
        return out.toByteArray();
    }

}
