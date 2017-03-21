package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.settings.HAClientSettings;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.mockito.Mockito.when;

public class HAClientTest {

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "Invalid input parameter. KSI signing clients list must be present")
    public void testAddingNullSigningClientList() throws Exception {
        new HAClient(null);
    }

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "Invalid input parameter. KSI signing clients list must contain at least one " +
                    "element")
    public void testAddingEmptySigningClientList() throws Exception {
        new HAClient(Collections.<KSISigningClient>emptyList());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. All the KSI " +
            "signing clients must have the same service credentials")
    public void testAddingSigningClientsWithDifferentCredentialsWillResultToAnError() throws Exception {
        KSISigningClient client1 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client2 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client3 = Mockito.mock(KSISigningClient.class);
        KSIServiceCredentials credentials1 = new KSIServiceCredentials("1", "1");
        KSIServiceCredentials credentials2 = new KSIServiceCredentials("2", "2");
        when(client1.getServiceCredentials()).thenReturn(credentials1);
        when(client2.getServiceCredentials()).thenReturn(credentials1);
        when(client3.getServiceCredentials()).thenReturn(credentials2);
        when(client1.getPduVersion()).thenReturn(PduVersion.V1);
        when(client2.getPduVersion()).thenReturn(PduVersion.V1);
        when(client3.getPduVersion()).thenReturn(PduVersion.V1);
        new HAClient(Arrays.asList(client1, client2, client3));
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. All the KSI " +
            "signing clients must have the same PDU version")
    public void testAddingSigningClientsWithDifferentPduVersions() throws Exception {
        KSISigningClient client1 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client2 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client3 = Mockito.mock(KSISigningClient.class);
        KSIServiceCredentials credentials = new KSIServiceCredentials("1", "1");
        when(client1.getServiceCredentials()).thenReturn(credentials);
        when(client2.getServiceCredentials()).thenReturn(credentials);
        when(client3.getServiceCredentials()).thenReturn(credentials);
        when(client1.getPduVersion()).thenReturn(PduVersion.V1);
        when(client2.getPduVersion()).thenReturn(PduVersion.V2);
        when(client3.getPduVersion()).thenReturn(PduVersion.V1);
        new HAClient(Arrays.asList(client1, client2, client3));
    }

    @Test
    public void testGettingServiceCredentials() throws Exception {
        KSISigningClient client1 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client2 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client3 = Mockito.mock(KSISigningClient.class);
        KSIServiceCredentials credentials = new KSIServiceCredentials("1", "1");
        when(client1.getServiceCredentials()).thenReturn(credentials);
        when(client2.getServiceCredentials()).thenReturn(credentials);
        when(client3.getServiceCredentials()).thenReturn(credentials);
        when(client1.getPduVersion()).thenReturn(PduVersion.V1);
        when(client2.getPduVersion()).thenReturn(PduVersion.V1);
        when(client3.getPduVersion()).thenReturn(PduVersion.V1);
        Assert.assertEquals(credentials, new HAClient(Arrays.asList(client1, client2, client3)).getServiceCredentials());
    }

    @Test
    public void testGettingPduVersion() throws Exception {
        KSISigningClient client1 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client2 = Mockito.mock(KSISigningClient.class);
        KSISigningClient client3 = Mockito.mock(KSISigningClient.class);
        KSIServiceCredentials credentials = new KSIServiceCredentials("1", "1");
        when(client1.getServiceCredentials()).thenReturn(credentials);
        when(client2.getServiceCredentials()).thenReturn(credentials);
        when(client3.getServiceCredentials()).thenReturn(credentials);
        when(client1.getPduVersion()).thenReturn(PduVersion.V1);
        when(client2.getPduVersion()).thenReturn(PduVersion.V1);
        when(client3.getPduVersion()).thenReturn(PduVersion.V1);
        Assert.assertEquals(PduVersion.V1, new HAClient(Arrays.asList(client1, client2, client3)).getPduVersion());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Property " +
            "HAClientSettings.aggregatorsPerRequest must not be larger than the list of given KSI signing clients")
    public void testActiveClientsPerRequestLargerThanSigningClientsList() throws Exception {
        KSISigningClient client1 = Mockito.mock(KSISigningClient.class);
        when(client1.getServiceCredentials()).thenReturn(new KSIServiceCredentials("1", "1"));
        when(client1.getPduVersion()).thenReturn(PduVersion.V1);
        new HAClient(Collections.singletonList(client1), new HAClientSettings(2, 1));
    }

}
