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
     * @param tcpClientSettings Settings for connecting to aggregator
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
