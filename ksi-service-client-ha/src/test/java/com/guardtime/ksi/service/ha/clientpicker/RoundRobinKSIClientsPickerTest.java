package com.guardtime.ksi.service.ha.clientpicker;

import com.guardtime.ksi.service.client.KSISigningClient;
import org.testng.annotations.Test;

import java.util.Collection;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class RoundRobinKSIClientsPickerTest {

    @Test
    public void testOneClientInSelection() throws Exception {
        KSISigningClient signingClient = mock(KSISigningClient.class);
        RoundRobinKSIClientsPicker picker = new RoundRobinKSIClientsPicker(singletonList(signingClient), 1);
        for (int i = 0; i < 10; i++) {
            Collection<KSISigningClient> chosenSelection = picker.pick();
            assertEquals(chosenSelection.size(), 1);
            assertTrue(chosenSelection.contains(signingClient));
        }
    }

    @Test
    public void testTwoClientsInSelectionOneInResult() throws Exception {
        KSISigningClient signingClient1 = mock(KSISigningClient.class);
        KSISigningClient signingClient2 = mock(KSISigningClient.class);
        RoundRobinKSIClientsPicker picker = new RoundRobinKSIClientsPicker(asList(signingClient1, signingClient2), 1);
        Collection<KSISigningClient> chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(signingClient1));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(signingClient2));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 1);
        assertTrue(chosenSelection.contains(signingClient1));
    }

    @Test
    public void testTwoClientsInSelectionTwoInResult() throws Exception {
        KSISigningClient signingClient1 = mock(KSISigningClient.class);
        KSISigningClient signingClient2 = mock(KSISigningClient.class);
        RoundRobinKSIClientsPicker picker = new RoundRobinKSIClientsPicker(asList(signingClient1, signingClient2), 2);
        for (int i = 0; i < 10; i++) {
            Collection<KSISigningClient> chosenSelection = picker.pick();
            assertEquals(chosenSelection.size(), 2);
            assertTrue(chosenSelection.contains(signingClient1));
            assertTrue(chosenSelection.contains(signingClient2));
        }
    }

    @Test
    public void testFiveClientsInSelectionThreeInResult() throws Exception {
        KSISigningClient signingClient1 = mock(KSISigningClient.class);
        KSISigningClient signingClient2 = mock(KSISigningClient.class);
        KSISigningClient signingClient3 = mock(KSISigningClient.class);
        KSISigningClient signingClient4 = mock(KSISigningClient.class);
        KSISigningClient signingClient5 = mock(KSISigningClient.class);
        RoundRobinKSIClientsPicker picker = new RoundRobinKSIClientsPicker(
                asList(signingClient1, signingClient2, signingClient3, signingClient4, signingClient5), 3);
        Collection<KSISigningClient> chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient1));
        assertTrue(chosenSelection.contains(signingClient2));
        assertTrue(chosenSelection.contains(signingClient3));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient2));
        assertTrue(chosenSelection.contains(signingClient3));
        assertTrue(chosenSelection.contains(signingClient4));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient3));
        assertTrue(chosenSelection.contains(signingClient4));
        assertTrue(chosenSelection.contains(signingClient5));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient4));
        assertTrue(chosenSelection.contains(signingClient5));
        assertTrue(chosenSelection.contains(signingClient1));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient5));
        assertTrue(chosenSelection.contains(signingClient1));
        assertTrue(chosenSelection.contains(signingClient2));
        chosenSelection = picker.pick();
        assertEquals(chosenSelection.size(), 3);
        assertTrue(chosenSelection.contains(signingClient1));
        assertTrue(chosenSelection.contains(signingClient2));
        assertTrue(chosenSelection.contains(signingClient3));
    }
}
