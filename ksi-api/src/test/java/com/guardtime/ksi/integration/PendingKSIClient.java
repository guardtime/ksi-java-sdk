package com.guardtime.ksi.integration;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

/**
 * Dummy KSI Client all of which's calls idle for one minute and then fail.
 */
public class PendingKSIClient implements KSISigningClient, KSIExtenderClient {
    
    public Future<ExtensionResponse> extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime)
            throws KSIException {
        sleep1M();
        throw new KSIClientException("Failure!");
    }

    public ExtenderConfiguration getExtenderConfiguration(KSIRequestContext requestContext) throws KSIException {
        throw new KSIClientException("Failure!");
    }
    
    public Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        sleep1M();
        throw new KSIClientException("Failure!");
    }

    public AggregatorConfiguration getAggregatorConfiguration(KSIRequestContext requestContext) throws KSIException {
        throw new KSIClientException("Failure!");
    }

    public void close() throws IOException {

    }

    private void sleep1M() {
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
