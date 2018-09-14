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
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.IOException;
import java.io.InputStream;

/**
 * KSI TCP client for signing.
 */
public class SigningTCPClient implements KSISigningClient {

    private final KSITCPClient ksitcpClient;

    /**
     * @param tcpClientSettings settings for connecting to aggregator
     */
    public SigningTCPClient(TCPClientSettings tcpClientSettings) {
        this.ksitcpClient = new KSITCPClient(tcpClientSettings);
    }

    /**
     * @see KSISigningClient#getServiceCredentials()
     */
    public ServiceCredentials getServiceCredentials() {
        return ksitcpClient.getServiceCredentials();
    }

    /**
     * @see KSISigningClient#getPduVersion()
     */
    public PduVersion getPduVersion() {
        return ksitcpClient.getPduVersion();
    }

    /**
     * @see KSISigningClient#sign(InputStream)
     */
    public Future<TLVElement> sign(InputStream request) throws KSIClientException {
        return ksitcpClient.sendRequest(request);
    }

    /**
     * @see KSISigningClient#close()
     */
    public void close() throws IOException {
        ksitcpClient.close();
    }

    @Override
    public String toString() {
        return "SigningTCPClient{ksitcpClient=" + ksitcpClient + "}";
    }
}
