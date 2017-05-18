/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationHandler;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.ConfigurationRequest;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class HAClientTest {

    private AggregatorConfiguration aggregatorConsolidatedConf;
    private ExtenderConfiguration extenderConsolidatedConf;

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize without any subclients")
    public void testInitSigningHaClientWithNull() {
        new SigningHAClient(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize without any subclients")
    public void testInitExtenderHaClientWithNull() {
        new ExtenderHAClient(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize without any subclients")
    public void testInitSigningHaClientWithEmptyList() {
        new SigningHAClient(Collections.<KSISigningClient>emptyList());
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize without any subclients")
    public void testInitExtenderHaClientWithEmptyList() {
        new ExtenderHAClient(Collections.<KSIExtenderClient>emptyList());
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "SigningHAClient can not be initialized with more than 3 subclients")
    public void testInitSigningHaClientWithTooMuchSubclients() throws Exception {
        new SigningHAClient(Arrays.asList(
                initSlowSigningClient(),
                initSlowSigningClient(),
                initSlowSigningClient(),
                initSlowSigningClient()));
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "ExtenderHAClient can not be initialized with more than 3 subclients")
    public void testInitExtenderHaClientWithTooMuchSubclients() throws Exception {
        new ExtenderHAClient(Arrays.asList(
                initSlowExtenderClient(),
                initSlowExtenderClient(),
                initSlowExtenderClient(),
                initSlowExtenderClient()));
    }

    @Test
    public void testOneAggregatorSucceedsOtherFail() throws Exception {
        AggregationResponse subclientResponse = mock(AggregationResponse.class);
        KSISigningClient succeedingClient = initSucceedingSigningClient(subclientResponse);
        SigningHAClient haClient = new SigningHAClient(Arrays.asList(
                initFailingSigningClient("Test failed. Client 1"),
                succeedingClient,
                initFailingSigningClient("Test failed. Client 3")
        ));
        AggregationResponse haClientResponse = haClient.sign(mock(DataHash.class), 0L).getResult();
        Assert.assertEquals(haClientResponse, subclientResponse);
    }


    @Test
    public void testOneExtenderSucceedsOtherFail() throws Exception {
        ExtensionResponse subclientResponse = mock(ExtensionResponse.class);
        KSIExtenderClient succeedingClient = initSucceedingExtenderClient(subclientResponse);
        ExtenderHAClient haClient = new ExtenderHAClient(Arrays.asList(
                initFailingExtenderClient("Test failed. Client 1"),
                succeedingClient,
                initFailingExtenderClient("Test failed. Client 3")
        ));
        ExtensionResponse haClientResponse = haClient.extend(mock(Date.class), mock(Date.class)).getResult();
        Assert.assertEquals(haClientResponse, subclientResponse);
    }

    @Test(timeOut = 1000)
    public void testOneAggregatorQuickOtherSlow() throws Exception {
        AggregationResponse subclientResponse = mock(AggregationResponse.class);
        SigningHAClient haClient = new SigningHAClient(Arrays.asList(
                initSlowSigningClient(),
                initSucceedingSigningClient(subclientResponse),
                initSlowSigningClient()
        ));
        AggregationResponse haClientResponse = haClient.sign(mock(DataHash.class), 0L).getResult();
        Assert.assertEquals(haClientResponse, subclientResponse);
    }

    @Test(timeOut = 1000)
    public void testOneExtenderQuickOtherSlow() throws Exception {
        ExtensionResponse subclientResponse = mock(ExtensionResponse.class);
        ExtenderHAClient haClient = new ExtenderHAClient(Arrays.asList(
                initSlowExtenderClient(),
                initSucceedingExtenderClient(subclientResponse),
                initSlowExtenderClient()
        ));
        ExtensionResponse haClientResponse = haClient.extend(mock(Date.class), mock(Date.class)).getResult();
        Assert.assertEquals(haClientResponse, subclientResponse);
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "All subclients of HAClient failed")
    public void testAllAggregatorsFail() throws Exception {
        SigningHAClient haClient = new SigningHAClient(Arrays.asList(
                initFailingSigningClient("Client failed. Client 1"),
                initFailingSigningClient("Client failed. Client 2"),
                initFailingSigningClient("Client failed. Client 3")
        ));
        haClient.sign(mock(DataHash.class), 0L).getResult();
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "All subclients of HAClient failed")
    public void testAllExtendersFail() throws Exception {
        ExtenderHAClient haClient = new ExtenderHAClient(Arrays.asList(
                initFailingExtenderClient("Client failed. Client 1"),
                initFailingExtenderClient("Client failed. Client 2"),
                initFailingExtenderClient("Client failed. Client 3")
        ));
        haClient.extend(new Date(), new Date()).getResult();
    }

    @Test
    public void testSigningConfigurationListening() throws Exception {
        final AsyncContext context = new AsyncContext(3);
        List<KSISigningClient> signingClients = new ArrayList<KSISigningClient>();
        signingClients.add(new DummyClient(300L));
        signingClients.add(new DummyClient(200L));
        signingClients.add(new DummyClient(100L));
        SigningHAClient signingHAClient = new SigningHAClient(signingClients);
        signingHAClient.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
            public void updated(AggregatorConfiguration configuration) {
                setConsolidatedConf(configuration);
                context.succeed();
            }

            public void updateFailed(Throwable t) {
                try {
                    Assert.fail("Configuration update failed", t);
                } catch (AssertionError e) {
                    context.fail(e);
                }
            }
        });
        signingHAClient.sendAggregationConfigurationRequest();
        context.await();
        assertEquals(aggregatorConsolidatedConf.getMaximumRequests(), new Long(300));
    }

    @Test
    public void testExtenderConfigurationListening() throws Exception {
        final AsyncContext context = new AsyncContext(3);
        List<KSIExtenderClient> extenderClients = new ArrayList<KSIExtenderClient>();
        extenderClients.add(new DummyClient(300L));
        extenderClients.add(new DummyClient(200L));
        extenderClients.add(new DummyClient(100L));
        ExtenderHAClient extenderHAClient = new ExtenderHAClient(extenderClients);
        extenderHAClient.registerExtenderConfigurationListener(new ConfigurationListener<ExtenderConfiguration>() {
            public void updated(ExtenderConfiguration configuration) {
                setConsolidatedConf(configuration);
                context.succeed();
            }

            public void updateFailed(Throwable t) {
                try {
                    Assert.fail("Configuration update failed", t);
                } catch (AssertionError e) {
                    context.fail(e);
                }
            }
        });
        extenderHAClient.sendExtenderConfigurationRequest();
        context.await();
        assertEquals(extenderConsolidatedConf.getMaximumRequests(), new Long(300));
    }

    private KSISigningClient initSucceedingSigningClient(final AggregationResponse subclientResponse) throws KSIException {
        KSISigningClient succeedingClient = mock(KSISigningClient.class);
        when(succeedingClient.sign(any(DataHash.class), anyLong())).thenReturn(new Future<AggregationResponse>() {
            public AggregationResponse getResult() throws KSIException {
                return subclientResponse;
            }

            public boolean isFinished() {
                return true;
            }
        });
        return succeedingClient;
    }

    private KSISigningClient initFailingSigningClient(String exMessage) throws KSIException {
        KSISigningClient subsigningClient = mock(KSISigningClient.class);
        when(subsigningClient.sign(any(DataHash.class), anyLong())).thenThrow(new RuntimeException(exMessage));
        return subsigningClient;
    }

    private KSIExtenderClient initSucceedingExtenderClient(final ExtensionResponse subclientResponse) throws KSIException {
        KSIExtenderClient succeedingClient = mock(KSIExtenderClient.class);
        when(succeedingClient.extend(any(Date.class), any(Date.class))).thenReturn(new Future<ExtensionResponse>() {
            public ExtensionResponse getResult() throws KSIException {
                return subclientResponse;
            }

            public boolean isFinished() {
                return true;
            }
        });
        return succeedingClient;
    }

    private KSIExtenderClient initFailingExtenderClient(String exMessage) throws KSIException {
        KSIExtenderClient subClient = mock(KSIExtenderClient.class);
        when(subClient.extend(any(Date.class), any(Date.class))).thenThrow(new RuntimeException(exMessage));
        return subClient;
    }

    private KSISigningClient initSlowSigningClient() throws KSIException {
        KSISigningClient client = mock(KSISigningClient.class);
        when(client.sign(any(DataHash.class), anyLong())).then(new Answer<Object>() {
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Thread.sleep(10000);
                return null;
            }
        });
        return client;
    }

    private KSIExtenderClient initSlowExtenderClient() throws KSIException {
        KSIExtenderClient client = mock(KSIExtenderClient.class);
        when(client.extend(any(Date.class), any(Date.class))).then(new Answer<Object>() {
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Thread.sleep(10000);
                return null;
            }
        });
        return client;
    }

    private void setConsolidatedConf(ExtenderConfiguration conf) {
        this.extenderConsolidatedConf = conf;
    }

    private void setConsolidatedConf(AggregatorConfiguration conf) {
        this.aggregatorConsolidatedConf = conf;
    }

    private static class DummyClient implements KSISigningClient, KSIExtenderClient {

        private final ConfigurationHandler<AggregatorConfiguration> aggrConfHandler = new ConfigurationHandler<AggregatorConfiguration>(DefaultExecutorServiceProvider.getExecutorService());
        private final ConfigurationHandler<ExtenderConfiguration> extenderConfHandler = new ConfigurationHandler<ExtenderConfiguration>(DefaultExecutorServiceProvider.getExecutorService());

        private final Long maxRequests;

        DummyClient(Long maxRequests) {
            this.maxRequests = maxRequests;
        }

        public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
            return null;
        }

        public List<KSIExtenderClient> getSubExtenderClients() {
            return Collections.emptyList();
        }

        public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
            extenderConfHandler.registerListener(listener);
        }

        public void sendExtenderConfigurationRequest() {
            extenderConfHandler.doConfigurationUpdate(new ConfigurationRequest<ExtenderConfiguration>() {
                public ExtenderConfiguration invoke() throws KSIException {
                    ExtenderConfiguration confMock = Mockito.mock(ExtenderConfiguration.class);
                    sleep(maxRequests); // Make sure better values take more time
                    Mockito.when(confMock.getMaximumRequests()).thenReturn(maxRequests);
                    return confMock;
                }
            });
        }

        public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
            return null;
        }

        public List<KSISigningClient> getSubSigningClients() {
            return Collections.emptyList();
        }

        public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
            aggrConfHandler.registerListener(listener);
        }

        public void sendAggregationConfigurationRequest() {
            aggrConfHandler.doConfigurationUpdate(new ConfigurationRequest<AggregatorConfiguration>() {
                public AggregatorConfiguration invoke() throws KSIException {
                    AggregatorConfiguration confMock = Mockito.mock(AggregatorConfiguration.class);
                    sleep(maxRequests); // Make sure better values take more time
                    Mockito.when(confMock.getMaximumRequests()).thenReturn(maxRequests);
                    return confMock;
                }
            });
        }

        public void close() throws IOException {

        }

        private void sleep(long millis) {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class AsyncContext {

        private CountDownLatch countDownLatch;
        private AtomicReference<AssertionError> potentialFailure = new AtomicReference<AssertionError>();

        AsyncContext(int initialLockCount) {
            this.countDownLatch = new CountDownLatch(initialLockCount);
        }

        void succeed() {
            countDownLatch.countDown();
        }

        void fail(AssertionError e) {
            potentialFailure.set(e);
        }

        void await() throws InterruptedException {
            int timeout = 4;
            if (!countDownLatch.await(timeout, TimeUnit.SECONDS)) {
                failIfError();
                Assert.fail("Test timed out after " + timeout + " seconds.");
            }
            failIfError();
        }

        private void failIfError() {
            AssertionError assertionError = potentialFailure.get();
            if (assertionError != null) {
                throw assertionError;
            }
        }
    }

}
