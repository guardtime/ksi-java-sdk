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

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduFactoryProvider;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationHandler;
import com.guardtime.ksi.service.client.ConfigurationRequest;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * KSI TCP client for signing.
 */
public class TCPClient implements KSISigningClient {

    private static final Logger logger = LoggerFactory.getLogger(TCPClient.class);

    private IoSession tcpSession;
    private ExecutorService executorService;
    private TCPClientSettings tcpClientSettings;
    private NioSocketConnector connector;
    private PduFactory pduFactory;
    private RequestContextFactory requestContextFactory = RequestContextFactory.DEFAULT_FACTORY;
    private ConfigurationHandler<AggregatorConfiguration> aggregatorConfHandler;

    public TCPClient(TCPClientSettings tcpClientSettings) {
        this(tcpClientSettings, DefaultExecutorServiceProvider.getExecutorService());
    }

    public TCPClient(TCPClientSettings tcpClientSettings, ExecutorService executorService) {
        Util.notNull(tcpClientSettings, "TCPClientSettings.tcpClientSettings");
        Util.notNull(executorService, "TCPClientSettings.executorService");
        this.pduFactory = PduFactoryProvider.get(tcpClientSettings.getPduVersion());
        this.tcpClientSettings = tcpClientSettings;
        this.connector = createConnector();
        this.executorService = executorService;
        aggregatorConfHandler = new ConfigurationHandler<AggregatorConfiguration>(executorService);
    }

    /**
     * Creates the PDU for signing request with correct aggregator login information and PDU version and sends it to gateway.
     * Parses the response PDU.
     *
     * @param dataHash - instance of {@link DataHash} to be signed. May not be null.
     * @param level - level of the dataHash to be signed in the overall tree. May not be null.
     *
     * @return {@link AggregationResponseFuture}
     * @throws KSIException
     */
    public AggregationResponseFuture sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = tcpClientSettings.getServiceCredentials();
        Future<TLVElement> requestFuture = sign(new ByteArrayInputStream(pduFactory.createAggregationRequest(requestContext, credentials, dataHash, level).toByteArray()));
        return new AggregationResponseFuture(requestFuture, requestContext, credentials, pduFactory);
    }

    private AggregatorConfiguration getAggregatorConfiguration() throws KSIException {
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = tcpClientSettings.getServiceCredentials();
        AggregationRequest requestMessage = pduFactory.createAggregatorConfigurationRequest(requestContext, credentials);
        Future<TLVElement> future = sign(new ByteArrayInputStream(requestMessage.toByteArray()));
        return pduFactory.readAggregatorConfigurationResponse(requestContext, credentials, future.getResult());
    }

    /**
     * Since this client does not have any subclients, it will always return an empty list.
     */
    public List<KSISigningClient> getSubSigningClients() {
        return Collections.emptyList();
    }

    protected Future<TLVElement> sign(InputStream request) throws KSIClientException {
        synchronized (this) {
            if (tcpSession == null || tcpSession.isClosing()) {
                this.tcpSession = createTcpSession();
            }
        }

        try {
            return new KSITCPRequestFuture(executorService.submit(new TCPTransactionHolder(request, tcpSession,
                    tcpClientSettings.getTcpTransactionTimeoutSec())));
        } catch (Throwable e) {
            throw new KSITCPTransactionException("There was a problem with initiating a TCP signing transaction with endpoint " +
                    tcpClientSettings.getEndpoint() + ".", e);
        }
    }

    public void close() {
        if (tcpSession != null) {
            tcpSession.closeOnFlush();
        }
        if (connector != null) {
            connector.dispose();
        }
    }

    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        aggregatorConfHandler.registerListener(listener);
    }

    private IoSession createTcpSession() throws KSITCPTransactionException {
        InetSocketAddress endpoint = tcpClientSettings.getEndpoint();
        logger.debug("Creating a new TCP session with host '{}'...", endpoint.getHostName());
        ConnectFuture connectFuture = connector.connect(endpoint);
        try {
            return connectFuture.await().getSession();
        } catch (Exception e) {
            connectFuture.cancel();
            throw new KSITCPTransactionException("Failed to initiate the TCP session with signer. Signer endpoint: " + endpoint, e);
        }
    }

    private NioSocketConnector createConnector() {
        NioSocketConnector connector = new NioSocketConnector();
        connector.setConnectTimeoutMillis(tcpClientSettings.getTcpTransactionTimeoutSec() * 1000);
        connector.getFilterChain().addLast("codec", new ProtocolCodecFilter(new TransactionCodecFactory()));
        connector.setHandler(new TCPSessionHandler());
        return connector;
    }

    @Override
    public String toString() {
        return "TCPClient{" +
                "Gateway='" + tcpClientSettings.getEndpoint() + "', " +
                "LoginID='" + tcpClientSettings.getServiceCredentials().getLoginId() + "', " +
                "PDUVersion='" + tcpClientSettings.getPduVersion() +
                "'}";
    }

    public void updateAggregationConfiguration() throws KSIException {
        aggregatorConfHandler.doConfigurationUpdate(new ConfigurationRequest<AggregatorConfiguration>() {
            public AggregatorConfiguration invoke() throws KSIException {
                return getAggregatorConfiguration();
            }
        });
    }
}
