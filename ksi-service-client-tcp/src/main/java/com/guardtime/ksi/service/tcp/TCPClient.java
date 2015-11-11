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

import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.NioSocketConnector;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * KSI TCP client for signing.
 */
public class TCPClient implements KSISigningClient {

    private IoSession tcpSession;
    private ExecutorService executorService;
    private TCPClientSettings tcpClientSettings;
    private TCPSessionHandler tcpSessionHandler;

    public TCPClient(TCPClientSettings tcpClientSettings) {
        this.tcpClientSettings = tcpClientSettings;
        executorService = Executors.newFixedThreadPool(tcpClientSettings.getTcpTransactionThreadPoolSize());
    }


    public Future<TLVElement> sign(InputStream request) throws KSITCPTransactionException {
        if (tcpSession == null) {
            tcpSession = createTCPSession();
        }
        try {
            return new KSITCPRequestFuture(executorService.submit(new TCPTransactionHolder(request, tcpSession, tcpClientSettings.getTcpTransactionTimeoutSec())));
        } catch (Throwable e) {
            throw new KSITCPTransactionException("There was a problem with initiating a TCP signing transaction with endpoint " +
                    tcpClientSettings.getEndpoint() + ".", e);
        }
    }

    public void close() {
        if (tcpSession != null) {
            tcpSessionHandler.closeSessionManually(tcpSession);
        }
    }

    public ServiceCredentials getServiceCredentials() {
        return tcpClientSettings.getServiceCredentials();
    }

    private IoSession createTCPSession() throws KSITCPTransactionException {

        InetSocketAddress endpoint = tcpClientSettings.getEndpoint();
        NioSocketConnector connector = new NioSocketConnector();
        connector.setConnectTimeoutMillis(tcpClientSettings.getTcpTransactionTimeoutSec() * 1000);
        connector.getFilterChain().addLast("codec", new ProtocolCodecFilter(new TransactionCodecFactory()));
        tcpSessionHandler = new TCPSessionHandler(connector);
        connector.setHandler(tcpSessionHandler);
        ConnectFuture connectFuture = connector.connect(endpoint);

        try {
            return connectFuture.await().getSession();
        } catch (Exception e) {
            throw new KSITCPTransactionException("Failed to initiate the TCP session with signer. Signer endpoint: " + endpoint, e);
        }
    }
}