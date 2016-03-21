/*
 * Copyright 2013-2015 Guardtime, Inc.
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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.service.aggregation.AggregationRequest;
import com.guardtime.ksi.service.aggregation.AggregationRequestPayload;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.extension.ExtensionRequest;
import com.guardtime.ksi.service.extension.ExtensionRequestPayload;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link KSIService} implementation
 */
public class KSIServiceImpl implements KSIService {

    private KSISigningClient signerClient;
    private KSIExtenderClient extenderClient;
    private KSIPublicationsFileClient publicationsFileClient;
    private KSISignatureFactory signatureFactory;
    private PublicationsFileFactory publicationsFileFactory;

    /**
     * Creates new instance of {@link KSIServiceImpl}.
     *
     * @param signerClient
     *         - KSI client to be used for signing. May not be null.
     * @param extenderClient
     *         - KSI HTTP client to be used for extending. May not be null.
     * @param publicationsFileClient
     *         - KSI HTTP client to be used for fetching the publications file. May not be null.
     */
    public KSIServiceImpl(KSISigningClient signerClient, KSIExtenderClient extenderClient, KSIPublicationsFileClient publicationsFileClient, KSISignatureFactory signatureFactory, PublicationsFileFactory publicationsFileFactory) throws KSIException {
        if (signerClient == null) {
            throw new KSIException("Invalid input parameter. Singer client can not be null");
        }
        if (extenderClient == null) {
            throw new KSIException("Invalid input parameter. Extender client can not be null");
        }
        if (publicationsFileClient == null) {
            throw new KSIException("Invalid input parameter. Publications file client can not be null");
        }
        if (signatureFactory == null) {
            throw new KSIException("Invalid input parameter. KSI signature factory can not be null");
        }
        if (publicationsFileFactory == null) {
            throw new KSIException("Invalid input parameter. Publications file factory can not be null");
        }
        this.signerClient = signerClient;
        this.extenderClient = extenderClient;
        this.publicationsFileClient = publicationsFileClient;
        this.signatureFactory = signatureFactory;
        this.publicationsFileFactory = publicationsFileFactory;
    }

    public CreateSignatureFuture sign(DataHash dataHash) throws KSIException {
        //TODO
       return sign(dataHash, 0L);
    }

    public CreateSignatureFuture sign(DataHash dataHash, long level) throws KSIException {
        Long requestId = generateRequestId();
        AggregationRequestPayload request = new AggregationRequestPayload(dataHash, requestId, level);
        ServiceCredentials credentials = signerClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, requestId);
        KSIMessageHeader header = new KSIMessageHeader(credentials.getLoginId(), PduIdentifiers.getInstanceId(), PduIdentifiers.getInstanceId());
        AggregationRequest requestMessage = new AggregationRequest(header, request, credentials.getLoginKey());
        Future<TLVElement> future = signerClient.sign(convert(requestMessage));
        return new CreateSignatureFuture(future, requestContext, signatureFactory);
    }

    /**
     * @param aggregationTime
     *         the time of the aggregation round from which the calendar hash chain should start. must not be null.
     * @param publicationTime
     *         the time of the calendar root hash value to which the aggregation hash value should be connected by the
     *         calendar hash chain.Its absence means a request for a calendar hash chain from aggregation time to the
     *         most recent calendar record the extension server has.
     * @return instance of {@link ExtensionRequestFuture}
     */
    public ExtensionRequestFuture extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Long requestId = generateRequestId();
        return extendSignature(new ExtensionRequestPayload(aggregationTime, publicationTime, requestId));
    }

    public Future<PublicationsFile> getPublicationsFile() throws KSIException {
        Future<ByteBuffer> future = publicationsFileClient.getPublicationsFile();
        return new PublicationsFileFuture(publicationsFileFactory, future);
    }

    protected Long generateRequestId() {
        return Util.nextLong();
    }

    private ExtensionRequestFuture extendSignature(ExtensionRequestPayload extensionRequest)
            throws KSIException {
        ServiceCredentials credentials = extenderClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, extensionRequest.getRequestId());
        KSIMessageHeader header = new KSIMessageHeader(credentials.getLoginId(), PduIdentifiers.getInstanceId(), PduIdentifiers.getInstanceId());
        ExtensionRequest requestMessage = new ExtensionRequest(header, extensionRequest, credentials.getLoginKey());
        ByteArrayInputStream inputStream = convert(requestMessage);
        Future<TLVElement> future = extenderClient.extend(inputStream);
        return new ExtensionRequestFuture(future, requestContext, signatureFactory);
    }

    private ByteArrayInputStream convert(TLVStructure request) throws KSIProtocolException {
        try {
            return new ByteArrayInputStream(request.getRootElement().getEncoded());
        } catch (TLVParserException e) {
            throw new KSIProtocolException("Request message converting failed", e);
        }
    }

    public KSIExtenderClient getExtenderClient() {
        return extenderClient;
    }

    public KSISigningClient getSignerClient() {
        return signerClient;
    }

    public KSIPublicationsFileClient getPublicationsFileClient() {
        return publicationsFileClient;
    }
}
