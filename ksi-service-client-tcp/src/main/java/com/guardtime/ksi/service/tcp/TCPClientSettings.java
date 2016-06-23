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

import com.guardtime.ksi.service.client.ServiceCredentials;

import java.net.InetSocketAddress;

/**
 * Class that holds all the properties needed to configure the TCPClient.
 */
public class TCPClientSettings {

    private InetSocketAddress endpoint;
    private int tcpTransactionTimeoutSec;
    private int tcpTransactionThreadPoolSize;
    private ServiceCredentials serviceCredentials;

    /**
     * Settings for TCP client.
     *
     * @param endpoint TCP signer endpoint address.
     * @param serviceCredentials Credentials for authenticating the client to the TCP signer.
     * @param tcpTransactionTimeoutSec Maximum time in seconds when a TCP transaction should time out from initiating the connection to receiving the whole response.
     * @param tcpTransactionThreadPoolSize Size of the thread pool for parallel TCP requests.
     */
    public TCPClientSettings(InetSocketAddress endpoint, int tcpTransactionTimeoutSec, int tcpTransactionThreadPoolSize, ServiceCredentials serviceCredentials) {
        this.endpoint = endpoint;
        this.tcpTransactionTimeoutSec = tcpTransactionTimeoutSec;
        this.tcpTransactionThreadPoolSize = tcpTransactionThreadPoolSize;
        this.serviceCredentials = serviceCredentials;
    }

    public InetSocketAddress getEndpoint() {
        return endpoint;
    }

    public int getTcpTransactionTimeoutSec() {
        return tcpTransactionTimeoutSec;
    }

    public int getTcpTransactionThreadPoolSize() {
        return tcpTransactionThreadPoolSize;
    }

    public ServiceCredentials getServiceCredentials() {
        return serviceCredentials;
    }
}
