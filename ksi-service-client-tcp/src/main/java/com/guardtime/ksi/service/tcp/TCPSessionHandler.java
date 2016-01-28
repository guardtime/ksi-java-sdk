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

import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class that handles different events that occur during the lifetime of TCP connection.
 */
class TCPSessionHandler implements IoHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TCPSessionHandler.class);

    private NioSocketConnector connector;

    private boolean sessionManuallyCosed = false;

    TCPSessionHandler(NioSocketConnector connector) {
        this.connector = connector;
    }

    public void exceptionCaught(IoSession session, Throwable t) throws Exception {
        LOGGER.error("An exception occurred while making a TCP request.", t);
    }

    public void messageReceived(IoSession session, Object message) throws Exception {
        ActiveTransactionsHolder.responseReceived((KSITCPSigningTransaction) message);
    }

    public void messageSent(IoSession session, Object message) throws Exception {
    }

    public void inputClosed(IoSession session) throws Exception {
    }

    public void sessionClosed(IoSession session) throws Exception {
        if (!sessionManuallyCosed) {
            reconnect(session);
        }
    }

    private void reconnect(IoSession session) {
        connector.connect(session.getRemoteAddress());
    }

    public void sessionCreated(IoSession session) throws Exception {
        LOGGER.debug("TCP session {} with signer created.", session.getId());
    }

    public void sessionIdle(IoSession session, IdleStatus idleStatus) throws Exception {
        LOGGER.debug("TCP session {} with signer is idle.", session.getId());
    }

    public void sessionOpened(IoSession session) throws Exception {
        LOGGER.debug("TCP session {} with signer is opened.", session.getId());
    }

    /**
     * Closes the given TCP session and sets the sessionManuallyClosed flag so that reconnecting would not be attempted.
     *
     * @param tcpSession - Session to close. Should be the same session that is handled by this handler.
     */
    public void closeSessionManually(IoSession tcpSession) {
        sessionManuallyCosed = true;
        tcpSession.getCloseFuture().awaitUninterruptibly();
    }
}