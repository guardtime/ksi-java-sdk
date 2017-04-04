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
package com.guardtime.ksi.service.client;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.ByteArrayInputStream;

/**
 * Abstract KSI Signing client for the type of clients which connect only to a single aggregator.
 */
public abstract class ExternalServiceConfigurationAwareSigningClient implements KSISigningClient, ExternalServiceConfigurationAwareClient {

    private final PduFactory pduFactory;

    protected ExternalServiceConfigurationAwareSigningClient(PduFactory pduFactory) {
        this.pduFactory = pduFactory;
    }

    /**
     * Creates the PDU for signing request with correct aggregator login information and PDU version and sends it to gateway.
     * Parses the response PDU.
     *
     * @param requestContext - instance of {@link KSIRequestContext}. May not be null.
     * @param dataHash - instance of {@link DataHash} to be signed. May not be null.
     * @param level - level of the dataHash to be signed in the overall tree. May not be null.
     *
     * @return {@link AggregationResponseFuture}
     * @throws KSIException
     */
    public AggregationResponseFuture sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        requestContext = requestContext.getWithCredentials(getServiceCredentials());
        Future<TLVElement> requestFuture = sign(new ByteArrayInputStream(pduFactory.createAggregationRequest(requestContext,
                dataHash, level).toByteArray()));
        return new AggregationResponseFuture(requestFuture, requestContext, pduFactory);
    }

}
