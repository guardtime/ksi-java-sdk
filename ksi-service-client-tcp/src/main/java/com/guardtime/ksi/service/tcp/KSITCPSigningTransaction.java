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

    private final BlockingQueue<TLVElement> availableResponse = new ArrayBlockingQueue<TLVElement>(1);
    private long correlationId;
    private TLVElement request;
    private TLVElement response;

    private KSITCPSigningTransaction() {
    }

    static KSITCPSigningTransaction fromRequest(InputStream request) throws IOException, KSIException {
        KSITCPSigningTransaction transaction = new KSITCPSigningTransaction();
        TLVElement tlv = TLVElement.create(Util.toByteArray(request));
        transaction.correlationId = extractTransactionIdFromRequestTLV(tlv);
        transaction.request = tlv;
        return transaction;
    }

    static KSITCPSigningTransaction fromResponse(IoBuffer ioBuffer) throws IOException, KSIException {
        KSITCPSigningTransaction transaction = new KSITCPSigningTransaction();
        byte[] responseData = new byte[ioBuffer.remaining()];
        ioBuffer.get(responseData);
        TLVElement tlv = parse(responseData);
        transaction.correlationId = extractTransactionIdFromResponseTLV(tlv);
        transaction.response = tlv;
        return transaction;
    }

    static TLVElement parse(byte[] data) throws KSIProtocolException {
        try {
            return TLVElement.create(data);
        } catch (MultipleTLVElementException e) {
            throw new KSIProtocolException("Invalid KSI response. Response message contains multiple TLV elements", e);
        } catch (TLVParserException e) {
            throw new KSIProtocolException("Can't parse response message", e);
        }
    }

    private static long extractTransactionIdFromRequestTLV(TLVElement tlvData) throws KSITCPTransactionException {
        try {
            return getRequestId(tlvData, REQUEST_WRAPPER_TAG);
        } catch (Exception e) {
            throw new KSITCPTransactionException("Request TLV was corrupt. Could not parse request ID.", e);
        }
    }

    private static long extractTransactionIdFromResponseTLV(TLVElement tlvData) throws KSITCPTransactionException {
        try {
            return getRequestId(tlvData, RESPONSE_WRAPPER_TAG);
        } catch (Exception e) {
            throw new KSITCPTransactionException("Response TLV was corrupt. Could not parse request ID.", e);
        }
    }

    private static Long getRequestId(TLVElement tlvData, int outerLayerTagName) throws TLVParserException {
        return tlvData.getFirstChildElement(outerLayerTagName).getFirstChildElement(REQ_ID_TAG).getDecodedLong();
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
    }

    void waitResponse(int timeoutSeconds) throws InterruptedException {
        availableResponse.poll(timeoutSeconds, TimeUnit.SECONDS);
    }

    WriteFuture send(IoSession session) {
        ActiveTransactionsHolder.put(this);
        return session.write(this);
    }

    void blockUntilResponseOrTimeout(WriteFuture writeFuture, int timeoutSec) throws KSITCPTransactionException {
        try {
            if (!writeFuture.await(timeoutSec, TimeUnit.SECONDS)) {
                throw new TCPTimeoutException("Request could not be sent in " + timeoutSec + " seconds.");
            }
            if (writeFuture.getException() != null) {
                throw new KSITCPTransactionException("An exception occurred with the TCP transaction.", writeFuture.getException());
            }
            waitResponse(timeoutSec);
            if (response == null) {
                throw new TCPTimeoutException("Response was not received in " + timeoutSec + " seconds.");
            }

        } catch (InterruptedException e) {
            throw new KSITCPTransactionException("Waiting for TCP response was interrupted.", e);
        } finally {
            ActiveTransactionsHolder.remove(this);
        }
    }
}
