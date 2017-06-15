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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static com.guardtime.ksi.util.Util.containsInt;

/**
 * Common PDU implementation for aggregation and extension request/response classes
 */
abstract class PduV2 extends TLVStructure {

    private static final Logger logger = LoggerFactory.getLogger(PduV2.class);

    private static final int[] PUSHABLE_ELEMENT_TYPES = new int[] {0x04};
    public static final int ELEMENT_TYPE_ACK = 0x05;

    protected List<TLVElement> payloads = new LinkedList<TLVElement>();
    private PduMessageHeader header;
    private MessageMac mac;

    /**
     * Constructor for creating a request PDU message
     */
    public PduV2(PduMessageHeader header, List<TLVElement> payloads, HashAlgorithm macAlgorithm, byte[] loginKey) throws KSIException {
        // root element
        this.rootElement = new TLVElement(false, false, getElementType());

        // pdu header
        this.rootElement.addChildElement(header.getRootElement());

        // pdu payloads
        for (TLVElement payloadElement : payloads) {
            if (!isSupportedPayloadElement(payloadElement)) {
                throw new IllegalArgumentException("TLV type 0x" + Integer.toHexString(payloadElement.getType()) + " isn't supported");
            }
            this.rootElement.addChildElement(payloadElement);
            this.payloads.add(payloadElement);
        }

        // calculate mac
        this.mac = new MessageMac(macAlgorithm);
        rootElement.addChildElement(mac.getRootElement());
        mac.setMac(calculateMac(macAlgorithm, loginKey));

        this.header = header;
    }

    /**
     * Constructor for reading a response PDU message
     */
    public PduV2(TLVElement rootElement, ServiceCredentials credentials) throws KSIException {
        super(rootElement);
        readMac(rootElement, credentials);
        readHeader(rootElement);
        readPayloads(rootElement);
        if (payloads.isEmpty()) {
            throw new KSIProtocolException("Invalid response message. Response message must contain at least one payload element");
        }
        checkErrorPayload();
    }

    /**
     * Returns the header of the PDU
     */
    public PduMessageHeader getHeader() {
        return header;
    }

    /**
     * Returns an array of supported PDU payload types
     */
    public abstract int[] getSupportedPayloadTypes();

    /**
     * In some cases where server lacks the information needed to populate header, request identifier, etc components
     * the special error payload is returned. This method returns the error payload type.
     */
    public int getErrorPayloadType() {
        return 0x03;
    }

    public List<TLVElement> getPayloads(int tlvType) throws TLVParserException {
        List<TLVElement> payloadElements = new ArrayList<TLVElement>();
        for (TLVElement payload : payloads) {
            if (payload.getType() == tlvType) {
                payloadElements.add(payload);
            } else if (!isPushableElement(payload) && payload.getType() != ELEMENT_TYPE_ACK) {
                logger.warn("Non-pushable payload with type=0x{} encountered", Integer.toHexString(payload.getType()));
            }
        }
        return payloadElements;
    }

    private void checkErrorPayload() throws KSIException {
        for (TLVElement payload : payloads) {
            if (payload.getType() == getErrorPayloadType()) {
                String status = getStatusCodeInHexString(payload);
                String errorMessage = getErrorMessage(payload);
                throw new KSIProtocolException("Error was returned by server. Error status is 0x" + status+ ". Error message from server: '" + errorMessage + "'");
            }
        }
    }

    private String getStatusCodeInHexString(TLVElement payload) throws TLVParserException {
        TLVElement statusTlv =  payload.getFirstChildElement(0x04);
        if (statusTlv != null) {
            return Long.toHexString(statusTlv.getDecodedLong());
        }
        return "";
    }

    private String getErrorMessage(TLVElement payload) throws TLVParserException {
        TLVElement errorMessageTlv =  payload.getFirstChildElement(0x05);
        if (errorMessageTlv != null) {
            return errorMessageTlv.getDecodedString();
        }
        return "";
    }

    private void readHeader(TLVElement rootElement) throws KSIException {
        TLVElement firstChild = rootElement.getFirstChildElement();
        if (isHeader(firstChild)) {
            this.header = new PduMessageHeader(firstChild);
        } else {
            throw new TLVParserException("Invalid PDU header element. Expected element 0x01, got 0x" + Long.toHexString(firstChild.getType()));
        }
    }

    private boolean isHeader(TLVElement element) {
        return element.getType() == PduMessageHeader.ELEMENT_TYPE_MESSAGE_HEADER;
    }


    private void readPayloads(TLVElement rootElement) throws TLVParserException {
        List<TLVElement> elements = rootElement.getChildElements();
        for (int i = header != null ? 1 : 0; i < elements.size() - 1; i++) {
            TLVElement element = elements.get(i);
            if (isSupportedPayloadElement(element)) {
                payloads.add(element);
            } else {
                verifyCriticalFlag(element);
                logger.info("Unknown non-critical TLV element with tag=0x{} encountered", Integer.toHexString(element.getType()));
            }
        }
    }

    private boolean isSupportedPayloadElement(TLVElement element) {
        int type = element.getType();
        return containsInt(getSupportedPayloadTypes(), type);
    }

    private boolean isPushableElement(TLVElement element) {
        int type = element.getType();
        return containsInt(PUSHABLE_ELEMENT_TYPES, type);
    }

    private void readMac(TLVElement rootElement, ServiceCredentials credentials) throws KSIException {
        TLVElement lastChild = rootElement.getLastChildElement();
        if (lastChild != null && lastChild.getType() == MessageMac.ELEMENT_TYPE) {
            this.mac = new MessageMac(lastChild);
            verifyMac(credentials);
        } else {
            TLVElement errorElement = rootElement.getFirstChildElement(getErrorPayloadType());
            if (errorElement != null) {
                throw new KSIProtocolException("Error was returned by server. Error status is 0x" + Long.toHexString(errorElement.getFirstChildElement(0x04).getDecodedLong()) + ". Error message from server: '" + errorElement.getFirstChildElement(0x05).getDecodedString() + "'");
            }
            logger.warn("Gateway sent a KSI response without MAC");
            throw new KSIProtocolException("Invalid KSI response. Missing MAC.");
        }
    }

    private void verifyMac(ServiceCredentials credentials) throws KSIException {
        DataHash macValue = mac.getMac();
        if (macValue.getAlgorithm() != credentials.getHmacAlgorithm()) {
            throw new KSIException(
                    "HMAC algorithm mismatch. Expected " + credentials.getHmacAlgorithm().getName() + ", received " + macValue.getAlgorithm().getName());
        }
        DataHash messageMac = calculateMac(macValue.getAlgorithm(), credentials.getLoginKey());
        if (!macValue.equals(messageMac)) {
            throw new InvalidMessageAuthenticationCodeException("Invalid MAC code. Expected " + macValue + ", calculated " + messageMac);
        }
    }

    private DataHash calculateMac(HashAlgorithm macAlgorithm, byte[] loginKey) throws KSIException {
        try {
            byte[] tlvBytes = rootElement.getEncoded();
            byte[] macCalculationInput = Util.copyOf(tlvBytes, 0, tlvBytes.length - macAlgorithm.getLength());
            return new DataHash(macAlgorithm, Util.calculateHMAC(macCalculationInput, loginKey, macAlgorithm.getName()));
        } catch (NoSuchAlgorithmException e) {
            throw new KSIException("MAC calculation failed. Invalid algorithm.", e);
        } catch (InvalidKeyException e) {
            throw new KSIException("MAC calculation failed. Invalid key.", e);
        }
    }

    private class MessageMac extends TLVStructure {

        public static final int ELEMENT_TYPE = 0x1F;

        private DataHash mac;

        public MessageMac(HashAlgorithm algorithm) throws KSIException {
            this.rootElement = TLVElement.create(getElementType(), new DataHash(algorithm, new byte[algorithm.getLength()]));
        }

        public MessageMac(TLVElement element) throws KSIException {
            super(element);
            this.mac = element.getDecodedDataHash();
        }

        public DataHash getMac() {
            return mac;
        }

        public void setMac(DataHash mac) throws TLVParserException {
            this.rootElement.setDataHashContent(mac);
            this.mac = mac;
        }

        @Override
        public int getElementType() {
            return ELEMENT_TYPE;
        }
    }

}
