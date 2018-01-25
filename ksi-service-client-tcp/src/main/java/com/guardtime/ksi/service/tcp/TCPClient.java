/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

/**
 * KSI TCP client for signing and extending.
 */
public class TCPClient implements KSISigningClient, KSIExtenderClient {

    private static final Logger logger = LoggerFactory.getLogger(TCPClient.class);

    private final SigningTCPClient signingTCPClient;
    private final ExtenderTCPClient extenderTCPClient;

    /**
     * @param signingSettings settings for the aggregator connection.
     *
     * @deprecated Use {@link SigningTCPClient#SigningTCPClient(TCPClientSettings)} or {@link #TCPClient(TCPClientSettings, TCPClientSettings)}
     * instead.
     *
     * <b>WARNING!</b> Using this constructor only configures the aggregator connection and the extending will not be usable.
     */
    @Deprecated
    public TCPClient(TCPClientSettings signingSettings) {
        Util.notNull(signingSettings, "TCPClientSettings.signingSettings");
        logger.warn("Constructor TCPClient(TCPClientSetting settings) is deprecated. It only configures aggregator connection. " +
                "Use either class SigningTCPClient or constructor TCPClient(TCPClientSetting signingSettings, " +
                "TCPClientSetting extendingSettings)");
        this.signingTCPClient = new SigningTCPClient(signingSettings);
        this.extenderTCPClient = null;
    }

    /**
     * @param signingSettings settings for the aggregator connection.
     * @param extendingSettings settings for the extender connection.
     */
    public TCPClient(TCPClientSettings signingSettings, TCPClientSettings extendingSettings) {
        Util.notNull(signingSettings, "TCPClientSettings.signingSettings");
        Util.notNull(signingSettings, "TCPClientSettings.extendingSettings");
        if (signingSettings.getPduVersion() != extendingSettings.getPduVersion()) {
            throw new IllegalArgumentException("TCPClient.signingSettings.pduVersion and " +
                    "TCPClient.extendingSettings.pduVersion must match. Use SigningTCPClient and ExtenderTCPClient " +
                    "if they do not match");
        }
        if (!signingSettings.getServiceCredentials().equals(extendingSettings.getServiceCredentials())) {
            throw new IllegalArgumentException("TCPClient.signingSettings.serviceCredentials and " +
                    "TCPClient.extendingSettings.serviceCredentials must match. Use SigningTCPClient and ExtenderTCPClient " +
                    "if they do not match");
        }
        this.signingTCPClient = new SigningTCPClient(signingSettings);
        this.extenderTCPClient = new ExtenderTCPClient(extendingSettings);
    }

    /**
     * @see SigningTCPClient#sign(InputStream)
     */
    public Future<TLVElement> sign(InputStream request) throws KSIClientException {
        return signingTCPClient.sign(request);
    }

    /**
     * @see ExtenderTCPClient#extend(InputStream)
     */
    public Future<TLVElement> extend(InputStream request) throws KSIClientException {
        if (extenderTCPClient == null) {
            throw new KSIClientException("Extender connection is not configured. This means that you have used the deprecated " +
                    "constructor to initialize this client. If you'd like to use TCPClient for both signing and extending use " +
                    "constructor TCPClient(TCPClientSettings signingSettings, TCPClientSettings extendingSettings) or if you'd " +
                    "like to use TCP client only for signing, use SigningTCPClient");
        }
        return extenderTCPClient.extend(request);
    }

    /**
     * Closes both the signing client and extending client.
     *
     * @see SigningTCPClient#close()
     * @see ExtenderTCPClient#close()
     */
    public void close() {
        try {
            signingTCPClient.close();
        } catch (Exception ignored) {
        }
        try {
            extenderTCPClient.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * @return Service credentials of gateway. Those apply both to extender and aggregator.
     */
    public ServiceCredentials getServiceCredentials() {
        return signingTCPClient.getServiceCredentials();
    }

    /**
     * @return PDU version of gateway. This applies both to extender and aggregator.
     */
    public PduVersion getPduVersion() {
        return signingTCPClient.getPduVersion();
    }

    @Override
    public String toString() {
        return "TCPClient{" +
                "SigningTCPClient='" + signingTCPClient + "', " +
                "ExtenderTCPClient='" + extenderTCPClient + "" +
                "'}";
    }
}
