/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */
package com.guardtime.ksi.service.tcp;

import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles different events that occur during the lifetime of TCP connection.
 */
class TCPSessionHandler implements IoHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TCPSessionHandler.class);

    public void exceptionCaught(IoSession session, Throwable t) throws Exception {
        LOGGER.error("An exception occurred while making a TCP request.", t);
        session.closeNow();
    }

    public void messageReceived(IoSession session, Object message) throws Exception {
        LOGGER.debug("Message received. {}", message);
        ActiveTransactionsHolder.responseReceived((KSITCPTransaction) message);
    }

    public void messageSent(IoSession session, Object message) throws Exception {
        LOGGER.debug("Message sent. {}", message);
    }

    public void inputClosed(IoSession session) throws Exception {
        session.closeNow();
    }

    public void sessionClosed(IoSession session) throws Exception {
    }

    public void sessionCreated(IoSession session) throws Exception {
        LOGGER.debug("TCP session ID={} created.", session.getId());
    }

    public void sessionIdle(IoSession session, IdleStatus idleStatus) throws Exception {
        LOGGER.debug("TCP session ID={} is idle.", session.getId());
    }

    public void sessionOpened(IoSession session) throws Exception {
        LOGGER.debug("TCP session ID={} is opened.", session.getId());
    }
}
