package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.IOException;
import java.io.InputStream;

public class SigningTCPClient implements KSISigningClient {

    private final KSITCPClient ksitcpClient;

    public SigningTCPClient(TCPClientSettings tcpClientSettings) {
        this.ksitcpClient = new KSITCPClient(tcpClientSettings);
    }

    public ServiceCredentials getServiceCredentials() {
        return ksitcpClient.getServiceCredentials();
    }

    public PduVersion getPduVersion() {
        return ksitcpClient.getPduVersion();
    }

    public Future<TLVElement> sign(InputStream request) throws KSIClientException {
        return ksitcpClient.sendRequest(request);
    }

    public void close() throws IOException {
        ksitcpClient.close();
    }

    @Override
    public String toString() {
        return "SigningTCPClient{" +
                "ksitcpClient=" + ksitcpClient +
                '}';
    }
}
