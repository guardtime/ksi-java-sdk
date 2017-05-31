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

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/**
 * Class that hold the initiated TCP request and from which the response can be asked for.
 */
class KSITCPRequestFuture implements com.guardtime.ksi.service.Future<TLVElement> {

    private KSITCPSigningTransaction transaction;
    private final long timeoutSec;
    private final WriteFuture writeFuture;
    private long transactionStartedMillis = System.currentTimeMillis();
    private TLVElement response;
    private KSITCPTransactionException exception;
    private boolean finished;

    KSITCPRequestFuture(InputStream request, IoSession tcpSession, int timeoutSec) throws IOException, KSIException {
        this.transaction = KSITCPSigningTransaction.fromRequest(request);
        ActiveTransactionsHolder.put(transaction);
        this.timeoutSec = timeoutSec;
        this.writeFuture = transaction.send(tcpSession);
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
        try {
            boolean written = writeFuture.await(timeoutSec, TimeUnit.SECONDS);
            if (!written) {
                exception = new TCPTimeoutException("TCP request sending could not be completed in " + timeoutSec + " seconds");
                throw exception;
            }
            int timeoutSeconds = getSecondsLeftBeforeTimeout();
            response = transaction.waitResponse(timeoutSeconds);
            if (response == null) {
                exception = new TCPTimeoutException("Response was not received in " + timeoutSec + " seconds");
                throw exception;
            }
            return response;
        } catch (InterruptedException e) {
            exception = new KSITCPTransactionException("TCP transaction was interrupted", e);
            throw exception;
        } finally {
            finished = true;
            ActiveTransactionsHolder.remove(transaction);
        }
    }

    private int getSecondsLeftBeforeTimeout() {
        long now = System.currentTimeMillis();
        long timePassed = now - transactionStartedMillis;
        int timeoutSeconds = (int) Math.ceil(((timeoutSec * 1000) - timePassed) / 1000);
        if (timeoutSeconds < 0) timeoutSeconds = 0;
        return timeoutSeconds;
    }

    /**
     * @return Is the TCP request finished.
     */
    public boolean isFinished() {
        if (finished) {
            return true;
        }
        long now = System.currentTimeMillis();
        long timePassed = now - transactionStartedMillis;
        return timePassed > (timeoutSec * 1000);
    }
}
