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
package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.MultipleTLVElementException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.util.Util;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Class that represents a single TCP signing transaction.
 */
class KSITCPSigningTransaction {

    private static final int REQUEST_WRAPPER_TAG = 0x201;
    private static final int RESPONSE_WRAPPER_TAG = 0x202;
    private static final int REQ_ID_TAG = 0x1;
    private static final int PDU_V2_PAYLOAD_ELEMENT_TAG = 0x02;

    private final BlockingQueue<TLVElement> availableResponse = new ArrayBlockingQueue<TLVElement>(1);
    private long correlationId;
    private TLVElement request;
    private TLVElement response;
    private static final Object CONF_REQUEST_LOCK = new Object();
    private static Long confRequestId = 0L;

    private KSITCPSigningTransaction() {
    }

    static KSITCPSigningTransaction fromRequest(InputStream request) throws IOException, KSIException {
        KSITCPSigningTransaction transaction = new KSITCPSigningTransaction();
        TLVElement tlv = TLVElement.create(Util.toByteArray(request));
        transaction.correlationId = isConfigurationPayload(tlv) ? getNewConfId() : extractTransactionIdFromRequestTLV(tlv);
        transaction.request = tlv;
        return transaction;
    }

    static KSITCPSigningTransaction fromResponse(IoBuffer ioBuffer) throws KSIException {
        KSITCPSigningTransaction transaction = new KSITCPSigningTransaction();
        byte[] responseData = new byte[ioBuffer.remaining()];
        ioBuffer.get(responseData);
        TLVElement tlv = parse(responseData);

        if (isConfigurationPayload(tlv)) {
            synchronized (CONF_REQUEST_LOCK) {
                transaction.correlationId = confRequestId;
                confRequestId = confRequestId + 1;
            }
        } else {
            transaction.correlationId = extractTransactionIdFromResponseTLV(tlv);
        }


        transaction.response = tlv;
        return transaction;
    }

    private static long getNewConfId() {
        synchronized (CONF_REQUEST_LOCK) {
            return --confRequestId;
        }
    }

    private static TLVElement parse(byte[] data) throws KSIProtocolException {
        try {
            return TLVElement.create(data);
        } catch (MultipleTLVElementException e) {
            throw new KSIProtocolException("Invalid KSI response. Response message contains multiple TLV elements", e);
        } catch (TLVParserException e) {
            throw new KSIProtocolException("Can't parse response message", e);
        }
    }

    private static boolean isConfigurationPayload(TLVElement tlv) {
        if (tlv.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_REQUEST_PDU_V2 ||
                tlv.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2) {
            return tlv.getFirstChildElement(0x04) != null;
        }
        return false;
    }

    private static long extractTransactionIdFromRequestTLV(TLVElement tlvData) throws KSITCPTransactionException {
        try {
            if (tlvData.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_REQUEST_PDU_V2) {
                return extractRequestId(tlvData, PDU_V2_PAYLOAD_ELEMENT_TAG);
            }
            return extractRequestId(tlvData, REQUEST_WRAPPER_TAG);
        } catch (Exception e) {
            throw new KSITCPTransactionException("Request TLV was corrupt. Could not parse request ID.", e);
        }
    }

    private static long extractTransactionIdFromResponseTLV(TLVElement tlvData) throws KSITCPTransactionException {
        try {
            if (tlvData.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2) {
                return extractRequestId(tlvData, PDU_V2_PAYLOAD_ELEMENT_TAG);
            }
            return extractRequestId(tlvData, RESPONSE_WRAPPER_TAG);
        } catch (Exception e) {
            throw new KSITCPTransactionException("Response TLV was corrupt. Could not parse request ID.", e);
        }
    }

    private static long extractRequestId(TLVElement tlvData, int outerLayerTagName) throws TLVParserException {
        TLVElement payloadElementTag = tlvData.getFirstChildElement(outerLayerTagName);
        if (payloadElementTag == null) {
            throw new IllegalStateException("TLV does not contain payload element tag");
        }
        TLVElement reqIdTag = payloadElementTag.getFirstChildElement(REQ_ID_TAG);
        if (reqIdTag == null) {
            throw new IllegalStateException("Payload element tag does not contain request ID tag");
        }
        return reqIdTag.getDecodedLong();
    }

    long getCorrelationId() {
        return correlationId;
    }

    TLVElement getRequest() {
        return request;
    }


    TLVElement getResponse() {
        return response;
    }

    void responseReceived(TLVElement response) {
        this.response = response;
        availableResponse.offer(response);
        ActiveTransactionsHolder.remove(this);
    }

    TLVElement waitResponse(long timeoutMs) throws InterruptedException {
        return availableResponse.poll(timeoutMs, TimeUnit.MILLISECONDS);
    }

    WriteFuture send(IoSession session) {
        return session.write(this);
    }
}
