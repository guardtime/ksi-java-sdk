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

import com.guardtime.ksi.tlv.TLVElement;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.session.IoSession;

import java.io.InputStream;
import java.util.concurrent.Callable;

/**
 * Class that holds TCP transaction. This is given to ThreadPoolExecutor for asynchronous request.
 */
class TCPTransactionHolder implements Callable<TLVElement> {

    private KSITCPSigningTransaction transaction;
    private WriteFuture writeFuture;
    private int timeoutSec;

    TCPTransactionHolder(InputStream request, IoSession session, int timeoutSec) throws Throwable {
        this.transaction = KSITCPSigningTransaction.fromRequest(request);
        this.writeFuture = transaction.send(session);
        this.timeoutSec = timeoutSec;
    }

    public TLVElement call() throws Exception {
        transaction.blockUntilResponseOrTimeout(writeFuture, timeoutSec);
        return transaction.getResponse();
    }
}
