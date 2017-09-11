package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class TCPClientTest {

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp =
            "TCPClient.signingSettings.pduVersion and TCPClient.extendingSettings.pduVersion must match. " +
                    "Use SigningTCPClient and ExtenderTCPClient if they do not match")
    public void testPduVersionsMismatch() {
        new TCPClient(new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials("anon", "anon"), PduVersion.V1),
                new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials("anon", "anon"), PduVersion.V2));
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp =
            "TCPClient.signingSettings.serviceCredentials and TCPClient.extendingSettings.serviceCredentials must match. " +
                    "Use SigningTCPClient and ExtenderTCPClient if they do not match")
    public void testServiceCredentialsMismatch() {
        new TCPClient(new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials("anon1", "anon1"), PduVersion.V1),
                new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials("anon2", "anon2"), PduVersion.V1));
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "Extender connection is not configured.*")
    public void testExtendingIfOnlySigningIsConfigured() throws Exception {
        TCPClient tcpClient = new TCPClient(
                new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials("anon", "anon"), PduVersion.V1));
        tcpClient.extend(new ByteArrayInputStream(new byte[]{0}));
    }

}
