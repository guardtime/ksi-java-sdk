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
import com.guardtime.ksi.tlv.TLVElement;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/**
 * Class that hold the initiated TCP request and from which the response can be asked for.
 */
class KSITCPRequestFuture implements com.guardtime.ksi.service.Future<TLVElement> {

    private static final Logger logger = LoggerFactory.getLogger(KSITCPRequestFuture.class);

    private KSITCPTransaction transaction;
    private final long timeoutMs;
    private WriteFuture writeFuture;
    private long transactionStartedMillis;
    private TLVElement response;
    private KSITCPTransactionException exception;
    private boolean finished;

    KSITCPRequestFuture(InputStream request, IoSession tcpSession, long timeoutMs) throws IOException, KSIException {
        this.timeoutMs = timeoutMs;
        startTransaction(tcpSession, request);
    }

    private void startTransaction(IoSession tcpSession, InputStream request) throws IOException, KSIException {
        this.transaction = KSITCPTransaction.fromRequest(request);
        transactionStartedMillis = System.currentTimeMillis();
        this.writeFuture = transaction.send(tcpSession);
        ActiveTransactionsHolder.put(transaction);
    }

    /**
     * This method blocks until response timeout occurs or the response arrives.
     *
     * @return Bytes of the TCP response.
     */
    public synchronized TLVElement getResult() throws KSITCPTransactionException {
        if (finished) {
            if (response != null) {
                return response;
            }
            if (exception != null) {
                throw exception;
            }
        }
        return blockUntilTransactionFinished();
    }

    private TLVElement blockUntilTransactionFinished() throws KSITCPTransactionException {
        try {
            boolean written = writeFuture.await(timeoutMs, TimeUnit.MILLISECONDS);
            if (!written) {
                throw saveException(new TCPTimeoutException("TCP request sending could not be completed in " + timeoutMs + " ms"));
            }

            long timeoutMs = getMsLeftBeforeTimeout();
            response = transaction.waitResponse(timeoutMs);

            if (response != null) {
                return response;
            } else {
                logger.debug("Message {} not received");
                throw saveException(new TCPTimeoutException("Response was not received in " + this.timeoutMs + " ms"));
            }
        } catch (InterruptedException e) {
            throw saveException(new KSITCPTransactionException("TCP transaction was interrupted", e));
        } finally {
            finished = true;
            ActiveTransactionsHolder.remove(transaction);
        }
    }

    private KSITCPTransactionException saveException(KSITCPTransactionException e) {
        this.exception = e;
        return e;
    }

    private long getMsLeftBeforeTimeout() {
        long timePassed = System.currentTimeMillis() - transactionStartedMillis;
        return Math.max(timeoutMs - timePassed, 0);
    }

    /**
     * @return Is the TCP request finished.
     */
    public boolean isFinished() {
        if (finished) {
            return true;
        }
        // If following is true, it means that it's now safe to call getResult() because it will time out immediately even if it is not ready
        return (System.currentTimeMillis() - transactionStartedMillis) > timeoutMs;
    }
}
