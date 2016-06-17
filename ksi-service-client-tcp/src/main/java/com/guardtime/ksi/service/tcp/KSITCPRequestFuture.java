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
package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * Class that hold the initiated TCP request and from which the response can be asked for.
 */
class KSITCPRequestFuture implements com.guardtime.ksi.service.Future<TLVElement> {

    private Future<TLVElement> responseFuture;

    public KSITCPRequestFuture(Future<TLVElement> responseFuture) {
        this.responseFuture = responseFuture;
    }

    /**
     * This method blocks until response timeout occurs or the response arrives.
     *
     * @return Bytes of the TCP response.
     */
    public TLVElement getResult() throws KSIProtocolException, KSITCPTransactionException {
        try {
            return responseFuture.get();
        } catch (InterruptedException e) {
            responseFuture.cancel(true);
            throw new KSITCPTransactionException("TCP transaction response waiting thread was interrupted.", e);
        } catch (ExecutionException e) {
            responseFuture.cancel(true);
            throw new KSITCPTransactionException("An exception occurred while executing TCP transaction.", e);
        }
    }

    /**
     * @return Is the TCP request finished.
     */
    public boolean isFinished() {
        return responseFuture.isDone();
    }
}
