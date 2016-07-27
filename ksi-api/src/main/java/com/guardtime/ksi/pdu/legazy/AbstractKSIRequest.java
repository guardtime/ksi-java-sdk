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
package com.guardtime.ksi.pdu.legazy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Contains the common logic for all KSI related request messages.
 */
abstract class AbstractKSIRequest<P extends TLVStructure> extends TLVStructure {

    private static final int ELEMENT_TYPE_MAC = 0x1F;

    private byte[] loginKey;
    private PduMessageHeader header;
    private P payload;
    private DataHash mac;

    public AbstractKSIRequest(PduMessageHeader header, P payload, byte[] loginKey) throws KSIException {
        this.loginKey = loginKey;
        this.header = header;
        this.payload = payload;
        this.rootElement = new TLVElement(false, false, getElementType());
        this.rootElement.addChildElement(header.getRootElement());

        if (payload != null) {
            this.rootElement.addChildElement(payload.getRootElement());
        }
        this.mac = calculateMac();
        TLVElement macElement = new TLVElement(false, false, ELEMENT_TYPE_MAC);
        macElement.setDataHashContent(mac);
        this.rootElement.addChildElement(macElement);
    }

    /**
     * Used to parse request TLV objects.
     *
     * @param element
     *         - instance of {@link TLVElement}
     * @param loginKey
     *         - login key byte array
     */
    public AbstractKSIRequest(TLVElement element, byte[] loginKey) throws KSIException {
        super(element);
        this.loginKey = loginKey;
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case PduMessageHeader.ELEMENT_TYPE_MESSAGE_HEADER:
                    this.header = new PduMessageHeader(readOnce(child));
                    continue;
                case LegacyAggregationRequestPayload.ELEMENT_TYPE:
                case LegacyExtensionRequestPayload.ELEMENT_TYPE:
                    this.payload = readPayload(readOnce(child));
                    continue;
                case ELEMENT_TYPE_MAC:
                    this.mac = readOnce(child).getDecodedDataHash();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (header == null) {
            throw new KSIProtocolException("Invalid KSI request. PDU request header is missing");
        }
        if (mac == null) {
            throw new KSIProtocolException("Invalid KSI request. PDU request mac is missing");
        }
    }

    protected abstract P readPayload(TLVElement element) throws KSIException;

    /**
     * Returns the header of the message.
     */
    public PduMessageHeader getHeader() {
        return this.header;
    }

    /**
     * Returns outgoing aggregation message HMAC
     */
    public DataHash getMac() {
        return this.mac;
    }

    /**
     * Returns instance of request payload.
     */
    public P getRequestPayload() {
        return payload;
    }

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
            return new DataHash(algorithm, Util.calculateHMAC(getContent(), this.loginKey, algorithm.getName()));
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
