package com.guardtime.ksi.service.client;

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.KSISigningService;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduFactoryProvider;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Adapter which wraps {@link KSISigningClient} so it can be used as {@link KSISigningService}.
 */
public final class KSISigningClientServiceAdapter implements KSISigningService {

    private final KSISigningClient client;
    private final RequestContextFactory requestContextFactory = RequestContextFactory.DEFAULT_FACTORY;
    private final ConfigurationHandler<AggregatorConfiguration> aggregatorConfHandler;
    private final PduFactory pduFactory;

    public KSISigningClientServiceAdapter(KSISigningClient client) {
        this(client, DefaultExecutorServiceProvider.getExecutorService());
    }

    public KSISigningClientServiceAdapter(KSISigningClient client, ExecutorService executorService) {
        Util.notNull(client, "KSISigningClientServiceAdapter.client");
        Util.notNull(executorService, "KSISigningClientServiceAdapter.executorService");
        this.client = client;
        this.pduFactory = PduFactoryProvider.get(client.getPduVersion());
        this.aggregatorConfHandler = new ConfigurationHandler<AggregatorConfiguration>(executorService);
    }

    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        KSIRequestContext requestContext = requestContextFactory.createContext();
        ServiceCredentials credentials = client.getServiceCredentials();
        Future<TLVElement> requestFuture = client.sign(new ByteArrayInputStream(pduFactory.createAggregationRequest(requestContext, credentials, dataHash, level).toByteArray()));
        return new AggregationResponseFuture(requestFuture, requestContext, credentials, pduFactory);
    }

    public List<KSISigningService> getSubSigningServices() {
        return Collections.emptyList();
    }

    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        aggregatorConfHandler.registerListener(listener);
    }

    public void sendAggregationConfigurationRequest() {
        aggregatorConfHandler.doConfigurationUpdate(new ConfigurationRequest<AggregatorConfiguration>() {
            public AggregatorConfiguration invoke() throws KSIException {
                KSIRequestContext requestContext = requestContextFactory.createContext();
                ServiceCredentials credentials = client.getServiceCredentials();
                AggregationRequest requestMessage = pduFactory.createAggregatorConfigurationRequest(requestContext, credentials);
                Future<TLVElement> future = client.sign(new ByteArrayInputStream(requestMessage.toByteArray()));
                return pduFactory.readAggregatorConfigurationResponse(requestContext, credentials, future.getResult());
            }
        });
    }

    public void close() throws IOException {
        client.close();
    }

    @Override
    public String toString() {
        return "KSISigningClientServiceAdapter{" +
                "client=" + client +
                '}';
    }
}
