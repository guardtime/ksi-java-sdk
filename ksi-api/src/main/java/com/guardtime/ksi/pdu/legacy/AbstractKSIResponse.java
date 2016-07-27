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
package com.guardtime.ksi.pdu.legacy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.service.*;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Contains the common logic for all KSI related responses.
 */
abstract class AbstractKSIResponse<T extends LegacyPduResponsePayload> extends TLVStructure {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractKSIResponse.class);
    private static final int ELEMENT_TYPE_AGGREGATION_ERROR_PAYLOAD = 0x0203;
    private static final int ELEMENT_TYPE_EXTENSION_ERROR_PAYLOAD = 0x0303;
    private static final int ELEMENT_TYPE_ERROR_CODE = 0x04;
    private static final int ELEMENT_TYPE_ERROR_MESSAGE = 0x05;
    private static final int ELEMENT_TYPE_MAC = 0x1F;

    /**
     * KSI message header
     */
    private PduMessageHeader header;

    /**
     * KSI response protocol data unit
     */
    private T response;

    /**
     * KSI message MAC code
     */
    private DataHash mac;

    /**
     * This constructor is used to parse response messages. Also does the basic validation.
     *
     * @param rootElement
     *         - instance of {@link TLVElement}. may not be null.
     * @param context
     *         - instance of {@link KSIRequestContext}. may not be null
     * @throws KSIProtocolException
     *         - will be thrown when TLV message parsing fails
     */
    public AbstractKSIResponse(TLVElement rootElement, KSIRequestContext context) throws KSIException {
        super(rootElement);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Incoming response message: {}", rootElement);
        }
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case PduMessageHeader.ELEMENT_TYPE_MESSAGE_HEADER:
                    this.header = new PduMessageHeader(readOnce(child));
                    continue;
                case ELEMENT_TYPE_AGGREGATION_ERROR_PAYLOAD:
                case ELEMENT_TYPE_EXTENSION_ERROR_PAYLOAD:
                    throwErrorPayloadException(child);
                case LegacyAggregationResponsePayload.ELEMENT_TYPE:
                case LegacyExtensionResponsePayload.ELEMENT_TYPE:
                    if (response != null) {
                        throw new KSIProtocolException("Invalid response message. Message contains multiple response payloads");
                    }
                    this.response = parse(child);
                    continue;
                case ELEMENT_TYPE_MAC:
                    this.mac = readOnce(child).getDecodedDataHash();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (header == null) {
            throw new KSIProtocolException("Invalid response message. Response message header is required");
        }
        if (mac == null) {
            throw new KSIProtocolException("Invalid response message. Response message mac tag is required");
        }
        validateMac(context.getLoginKey());
        if (response == null) {
            throw new KSIProtocolException("Response message does not contain response payload element");
        }
        Long requestId = context.getRequestId();
        if (requestId != null && !requestId.equals(response.getRequestId())) {
            throw new KSIProtocolException("request IDs do not match, sent '" + requestId + "'" + " received '" + response.getRequestId() + "'");
        }
        if (response.getError() != null && response.getError() > 0) {
            throw new KSIProtocolException(response.getError(), response.getErrorMessage());
        }

    }

    protected abstract T parse(TLVElement element) throws KSIException;

    public T getResponsePayload() {
        return response;
    }

    /**
     * This method is used to check MAC code.
     *
     * @param key
     *         - key to be used to calculate MAC code
     * @throws KSIException
     *         will be thrown when MAC code doesn't validate
     */
    private void validateMac(byte[] key) throws KSIException {
        try {
            // calculate and set the MAC value
            HashAlgorithm algorithm = mac.getAlgorithm();
            DataHash macValue = new DataHash(algorithm, Util.calculateHMAC(getContent(), key, algorithm.getName()));
            if (!mac.equals(macValue)) {
                throw new InvalidMessageAuthenticationCodeException("Invalid MAC code. Expected " + mac + ", calculated " + macValue);
            }
        } catch (IOException e) {
            throw new InvalidMessageAuthenticationCodeException("IO Exception occurred turning MAC calculation", e);
        } catch (InvalidKeyException e) {
            throw new InvalidMessageAuthenticationCodeException("Problem with HMAC key.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidMessageAuthenticationCodeException("Unsupported HMAC algorithm.", e);
        } catch (HashException e) {
            throw new KSIProtocolException("Hashing exception occurred when calculating KSI service response HMAC", e);
        }
    }

    /**
     * Reads error code and error message elements from given TLV element and throws KSI protocol exception containing
     * error information.
     *
     * @param child
     *         KSI protocol error element
     * @throws KSIProtocolException
     *         will be always thrown
     */
    private void throwErrorPayloadException(TLVElement child) throws KSIException {
        TLVElement errorCodeElement = child.getFirstChildElement(ELEMENT_TYPE_ERROR_CODE);
        TLVElement messageElement = child.getFirstChildElement(ELEMENT_TYPE_ERROR_MESSAGE);
        throw new KSIProtocolException(errorCodeElement.getDecodedLong(), "Response error " + errorCodeElement.getDecodedLong() + ": "
                + messageElement.getDecodedString());
    }

    /**
     * @return returns KSI protocol message bytes without MAC code,
     * @throws IOException
     *         if IO error occurs
     */
    private byte[] getContent() throws IOException, KSIException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        header.writeTo(out);
        TLVStructure payload = getResponsePayload();
        if (payload != null) {
            payload.writeTo(out);
        } else {
            out.write(Util.toByteArray(0));
        }
        return out.toByteArray();
    }

}
