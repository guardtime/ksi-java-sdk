package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class TCPClientTest {

    private static final TCPClientSettings TCP_SETTINGS_ANON_PDUV1 = createTCPSettings("anon", PduVersion.V1);
    private static final TCPClientSettings TCP_SETTINGS_ANON_PDUV2 = createTCPSettings("anon", PduVersion.V2);
    private static final TCPClientSettings TCP_SETTINGS_ANON2_PDUV1 = createTCPSettings("anon2", PduVersion.V1);

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp =
            "TCPClient.signingSettings.pduVersion and TCPClient.extendingSettings.pduVersion must match. " +
                    "Use SigningTCPClient and ExtenderTCPClient if they do not match")
    public void testPduVersionsMismatch() {
        new TCPClient(TCP_SETTINGS_ANON_PDUV1, TCP_SETTINGS_ANON_PDUV2);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp =
            "TCPClient.signingSettings.serviceCredentials and TCPClient.extendingSettings.serviceCredentials must match. " +
                    "Use SigningTCPClient and ExtenderTCPClient if they do not match")
    public void testServiceCredentialsMismatch() {
        new TCPClient(TCP_SETTINGS_ANON_PDUV1, TCP_SETTINGS_ANON2_PDUV1);
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp =
            "Extender connection is not configured.*")
    public void testExtendingIfOnlySigningIsConfigured() throws Exception {
        TCPClient tcpClient = new TCPClient(TCP_SETTINGS_ANON_PDUV1);
        tcpClient.extend(new ByteArrayInputStream(new byte[] {0}));
    }

    private static TCPClientSettings createTCPSettings(String userPass, PduVersion pduVersion) {
        return new TCPClientSettings("tcp://0.0.0.0:0", 10, new KSIServiceCredentials(userPass, userPass), pduVersion);
    }
}
