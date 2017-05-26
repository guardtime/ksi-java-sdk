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
import com.guardtime.ksi.pdu.KSIExtendingService;
import com.guardtime.ksi.pdu.KSISigningService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationHandler;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.ConfigurationRequest;
import com.guardtime.ksi.service.client.KSIClientException;
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

public class HAServiceTest {

    private AggregatorConfiguration aggregatorConsolidatedConf;
    private ExtenderConfiguration extenderConsolidatedConf;


    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize SigningHAService without any subservices")
    public void testInitSigningHaServiceWithEmptyList() {
        new SigningHAService.Builder().build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Can not initialize ExtendingHAService without any subservices")
    public void testInitExtendingHAServiceWithEmptyList() {
        new ExtendingHAService.Builder().build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "SigningHAService can not be initialized with more than 3 subservices")
    public void testInitSigningHaServiceWithTooMuchSubclients() throws Exception {
        new SigningHAService.Builder().setServices(Arrays.asList(
                initSlowSigningClient(),
                initSlowSigningClient(),
                initSlowSigningClient(),
                initSlowSigningClient())).build();
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "ExtendingHAService can not be initialized with more than 3 subservices")
    public void testInitExtendingHAServiceWithTooMuchSubclients() throws Exception {
        new ExtendingHAService.Builder().setServices(Arrays.asList(
                initSlowExtenderClient(),
                initSlowExtenderClient(),
                initSlowExtenderClient(),
                initSlowExtenderClient())).build();
    }

    @Test
    public void testOneAggregatorSucceedsOtherFail() throws Exception {
        AggregationResponse subclientResponse = mock(AggregationResponse.class);
        KSISigningService succeedingClient = initSucceedingSigningClient(subclientResponse);
        SigningHAService haService = new SigningHAService.Builder().setServices(Arrays.asList(
                initFailingSigningClient("Test failed. Client 1"),
                succeedingClient,
                initFailingSigningClient("Test failed. Client 3")))
                .build();
        AggregationResponse haServiceResponse = haService.sign(mock(DataHash.class), 0L).getResult();
        Assert.assertEquals(haServiceResponse, subclientResponse);
    }


    @Test
    public void testOneExtenderSucceedsOtherFail() throws Exception {
        ExtensionResponse subclientResponse = mock(ExtensionResponse.class);
        KSIExtendingService succeedingClient = initSucceedingExtenderClient(subclientResponse);

        ExtendingHAService haService = new ExtendingHAService.Builder().setServices(Arrays.asList(
                initFailingExtenderClient("Test failed. Client 1"),
                succeedingClient,
                initFailingExtenderClient("Test failed. Client 3")))
                .build();
        ExtensionResponse haServiceResponse = haService.extend(mock(Date.class), mock(Date.class)).getResult();
        Assert.assertEquals(haServiceResponse, subclientResponse);
    }

    @Test(timeOut = 1000)
    public void testOneAggregatorQuickOtherSlow() throws Exception {
        AggregationResponse subclientResponse = mock(AggregationResponse.class);
        SigningHAService haService = new SigningHAService.Builder().setServices(Arrays.asList(
                initSlowSigningClient(),
                initSucceedingSigningClient(subclientResponse),
                initSlowSigningClient()))
                .build();
        AggregationResponse haServiceResponse = haService.sign(mock(DataHash.class), 0L).getResult();
        Assert.assertEquals(haServiceResponse, subclientResponse);
    }

    @Test(timeOut = 1000)
    public void testOneExtenderQuickOtherSlow() throws Exception {
        ExtensionResponse subclientResponse = mock(ExtensionResponse.class);
        ExtendingHAService haService = new ExtendingHAService.Builder().setServices(Arrays.asList(
                initSlowExtenderClient(),
                initSucceedingExtenderClient(subclientResponse),
                initSlowExtenderClient()))
                .build();
        ExtensionResponse haServiceResponse = haService.extend(mock(Date.class), mock(Date.class)).getResult();
        Assert.assertEquals(haServiceResponse, subclientResponse);
    }

    @Test
    public void testGetSubclients() throws Exception {
        List<KSISigningService> signingServices = new ArrayList<KSISigningService>();
        signingServices.add(initSlowSigningClient());
        signingServices.add(initFailingSigningClient("Failrue!"));
        signingServices.add(initSucceedingSigningClient(mock(AggregationResponse.class)));

        List<KSIExtendingService> extendingServices = new ArrayList<KSIExtendingService>();
        extendingServices.add(initSlowExtenderClient());
        extendingServices.add(initFailingExtenderClient("Failrue!"));
        extendingServices.add(initSucceedingExtenderClient(mock(ExtensionResponse.class)));

        HAService haService = new HAService.Builder().setSigningServices(signingServices).setExtendingServices(extendingServices).build();
        List<KSIExtendingService> requestedExtenderClients = haService.getSubExtendingServices();
        List<KSISigningService> requestedSigningClients = haService.getSubSigningServices();

        for (int i = 0; i < 2; i++) {
            Assert.assertEquals(signingServices.get(i), requestedSigningClients.get(i));
            Assert.assertEquals(extendingServices.get(i), requestedExtenderClients.get(i));
        }
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "All subclients of HAService failed")
    public void testAllAggregatorsFail() throws Exception {
        SigningHAService haService = new SigningHAService.Builder().setServices(Arrays.asList(
                initFailingSigningClient("Client failed. Client 1"),
                initFailingSigningClient("Client failed. Client 2"),
                initFailingSigningClient("Client failed. Client 3")))
                .build();
        haService.sign(mock(DataHash.class), 0L).getResult();
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "All subclients of HAService failed")
    public void testAllExtendersFail() throws Exception {
        ExtendingHAService haService = new ExtendingHAService.Builder().setServices(Arrays.asList(
                initFailingExtenderClient("Client failed. Client 1"),
                initFailingExtenderClient("Client failed. Client 2"),
                initFailingExtenderClient("Client failed. Client 3")))
                .build();
        haService.extend(new Date(), new Date()).getResult();
    }

    @Test
    public void testSigningConfigurationListening() throws Exception {
        final AsyncContext context = new AsyncContext(3);
        List<KSISigningService> signingServices = new ArrayList<KSISigningService>();
        signingServices.add(new DummyClient(300L));
        signingServices.add(new DummyClient(200L));
        signingServices.add(new DummyClient(100L));
        SigningHAService signingHAService = new SigningHAService.Builder().setServices(signingServices).build();
        signingHAService.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
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
        signingHAService.sendAggregationConfigurationRequest();
        context.await();
        assertEquals(aggregatorConsolidatedConf.getMaximumRequests(), new Long(300));
    }

    @Test
    public void testExtenderConfigurationListening() throws Exception {
        final AsyncContext context = new AsyncContext(3);
        List<KSIExtendingService> extendingServices = new ArrayList<KSIExtendingService>();
        extendingServices.add(new DummyClient(300L));
        extendingServices.add(new DummyClient(200L));
        extendingServices.add(new DummyClient(100L));
        ExtendingHAService extendingHAService = new ExtendingHAService.Builder().setServices(extendingServices).build();
        extendingHAService.registerExtenderConfigurationListener(new ConfigurationListener<ExtenderConfiguration>() {
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
        extendingHAService.sendExtenderConfigurationRequest();
        context.await();
        assertEquals(extenderConsolidatedConf.getMaximumRequests(), new Long(300));
    }

    private KSISigningService initSucceedingSigningClient(final AggregationResponse subclientResponse) throws KSIException {
        KSISigningService succeedingClient = mock(KSISigningService.class);
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

    private KSISigningService initFailingSigningClient(String exMessage) throws KSIException {
        KSISigningService subsigningClient = mock(KSISigningService.class);
        when(subsigningClient.sign(any(DataHash.class), anyLong())).thenThrow(new RuntimeException(exMessage));
        return subsigningClient;
    }

    private KSIExtendingService initSucceedingExtenderClient(final ExtensionResponse subclientResponse) throws KSIException {
        KSIExtendingService succeedingClient = mock(KSIExtendingService.class);
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

    private KSIExtendingService initFailingExtenderClient(String exMessage) throws KSIException {
        KSIExtendingService subClient = mock(KSIExtendingService.class);
        when(subClient.extend(any(Date.class), any(Date.class))).thenThrow(new RuntimeException(exMessage));
        return subClient;
    }

    private KSISigningService initSlowSigningClient() throws KSIException {
        KSISigningService client = mock(KSISigningService.class);
        when(client.sign(any(DataHash.class), anyLong())).then(new Answer<Object>() {
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Thread.sleep(10000);
                return null;
            }
        });
        return client;
    }

    private KSIExtendingService initSlowExtenderClient() throws KSIException {
        KSIExtendingService client = mock(KSIExtendingService.class);
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

    private static class DummyClient implements KSISigningService, KSIExtendingService {

        private final ConfigurationHandler<AggregatorConfiguration> aggrConfHandler = new ConfigurationHandler<AggregatorConfiguration>(DefaultExecutorServiceProvider.getExecutorService());
        private final ConfigurationHandler<ExtenderConfiguration> extenderConfHandler = new ConfigurationHandler<ExtenderConfiguration>(DefaultExecutorServiceProvider.getExecutorService());

        private final Long maxRequests;

        DummyClient(Long maxRequests) {
            this.maxRequests = maxRequests;
        }

        public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
            return null;
        }

        public List<KSIExtendingService> getSubExtendingServices() {
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

        public List<KSISigningService> getSubSigningServices() {
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
