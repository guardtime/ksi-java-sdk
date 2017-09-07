package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

class KSITCPClient implements Closeable {

    private static final Logger logger = LoggerFactory.getLogger(TCPClient.class);

    private IoSession tcpSession;
    private final TCPClientSettings tcpClientSettings;
    private final NioSocketConnector connector;

    KSITCPClient(TCPClientSettings tcpClientSettings) {
        Util.notNull(tcpClientSettings, "KSITCPClient.tcpClientSettings");
        this.tcpClientSettings = tcpClientSettings;
        this.connector = createConnector();
    }

    Future<TLVElement> sendRequest(InputStream request) throws KSITCPTransactionException {
        synchronized (this) {
            if (tcpSession == null || tcpSession.isClosing()) {
                this.tcpSession = createTcpSession();
            }
        }

        try {
            return new KSITCPRequestFuture(request, tcpSession,
                    TimeUnit.SECONDS.toMillis(tcpClientSettings.getTcpTransactionTimeoutSec()));
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

    ServiceCredentials getServiceCredentials() {
        return tcpClientSettings.getServiceCredentials();
    }

    PduVersion getPduVersion() {
        return tcpClientSettings.getPduVersion();
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

}
