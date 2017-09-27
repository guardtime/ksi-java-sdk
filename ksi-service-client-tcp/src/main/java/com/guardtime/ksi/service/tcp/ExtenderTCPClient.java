package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.IOException;
import java.io.InputStream;

/**
 * KSI TCP client for extending.
 */
public class ExtenderTCPClient implements KSIExtenderClient {

    private final KSITCPClient ksitcpClient;

    /**
     * @param tcpClientSettings Settings for connecting to extender
     */
    public ExtenderTCPClient(TCPClientSettings tcpClientSettings) {
        this.ksitcpClient = new KSITCPClient(tcpClientSettings);
    }

    /**
     * @see KSIExtenderClient#getServiceCredentials()
     */
    public ServiceCredentials getServiceCredentials() {
        return ksitcpClient.getServiceCredentials();
    }

    /**
     * @see KSIExtenderClient#getPduVersion()
     */
    public PduVersion getPduVersion() {
        return ksitcpClient.getPduVersion();
    }

    /**
     * @see KSIExtenderClient#extend(InputStream)
     */
    public Future<TLVElement> extend(InputStream request) throws KSIClientException {
        return ksitcpClient.sendRequest(request);
    }

    /**
     * @see KSIExtenderClient#close()
     */
    public void close() throws IOException {
        ksitcpClient.close();
    }

    @Override
    public String toString() {
        return "ExtenderTCPClient{ksitcpClient=" + ksitcpClient + "}";
    }
}
