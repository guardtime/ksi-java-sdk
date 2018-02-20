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

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.ServiceCredentials;

import java.net.InetSocketAddress;
import java.net.URI;

/**
 * Holds all the properties needed to configure the TCPClient.
 *
 * <b>IMPORTANT!</b>
 * <p>When constructing the instance with a {@link InetSocketAddress} the IP of the endpoint is cached in this object. This can result to connection problems.</p>
 * <p>For use cases where this can be a problem we suggest using the constructor that takes the endpoint URI as a string.</p>
 */
public class TCPClientSettings {

    private URI uri;
    private InetSocketAddress endpoint;
    private final int tcpTransactionTimeoutSec;
    private final ServiceCredentials serviceCredentials;
    private final PduVersion pduVersion;

    /**
     * Settings for TCP client.
     *
     * @param endpoint TCP gateway endpoint address.
     * @param serviceCredentials credentials for authenticating the client to the TCP gateway.
     * @param tcpTransactionTimeoutSec maximum time in seconds when a TCP transaction should time out from initiating the connection to receiving the whole response.
     */
    public TCPClientSettings(InetSocketAddress endpoint, int tcpTransactionTimeoutSec, ServiceCredentials serviceCredentials) {
        this(endpoint, tcpTransactionTimeoutSec, serviceCredentials, PduVersion.V2);
    }

    public TCPClientSettings(InetSocketAddress endpoint, int tcpTransactionTimeoutSec, ServiceCredentials serviceCredentials, PduVersion pduVersion) {
        this.endpoint = endpoint;
        this.tcpTransactionTimeoutSec = tcpTransactionTimeoutSec;
        this.serviceCredentials = serviceCredentials;
        this.pduVersion = pduVersion;
    }

    /**
     * Settings for TCP client.
     * The created {@link TCPClientSettings} instance constructs a new {@link InetSocketAddress} for every {@link #getEndpoint()} call.
     *
     * @param uri                             string containing the URI of endpoint. Must be in format: &lt;protocol&gt;://&lt;host&gt;:&lt;port&gt;
     * @param tcpTransactionTimeoutSec        maximum time in seconds when a TCP transaction should time out from initiating the connection to receiving the whole response.
     * @param serviceCredentials              credentials for authenticating the client to the TCP gateway.
     * @param pduVersion                      PDU version used for communication.
     */
    public TCPClientSettings(String uri, int tcpTransactionTimeoutSec, ServiceCredentials serviceCredentials, PduVersion pduVersion) throws IllegalArgumentException {
        this.uri = getVerifiedUri(uri);
        this.tcpTransactionTimeoutSec = tcpTransactionTimeoutSec;
        this.serviceCredentials = serviceCredentials;
        this.pduVersion = pduVersion;
    }

    private URI getVerifiedUri(String uri) {
        URI parsedUri = URI.create(uri);
        if (parsedUri.getHost() == null || parsedUri.getPort() == -1) {
            throw new IllegalArgumentException("URI does not contain mandatory components");
        }
        return parsedUri;
    }

    /**
     * Returns either the {@link InetSocketAddress} provided to the constructor or a new instance for every invocation based on the {@link String} provided to the constructor.
     *
     * @return An instance of {@link InetSocketAddress}.
     */
    public InetSocketAddress getEndpoint() {
        return endpoint == null ? new InetSocketAddress(uri.getHost(), uri.getPort()) : endpoint;
    }

    public int getTcpTransactionTimeoutSec() {
        return tcpTransactionTimeoutSec;
    }

    public ServiceCredentials getServiceCredentials() {
        return serviceCredentials;
    }

    public PduVersion getPduVersion() {
        return pduVersion;
    }
}
