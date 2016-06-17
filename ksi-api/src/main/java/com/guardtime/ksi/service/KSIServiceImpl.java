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

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Date;

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

/**
 * {@link KSIService} implementation
 */
public class KSIServiceImpl implements KSIService {

    private static final long DEFAULT_LEVEL = 0L;
    private KSISigningClient signerClient;
    private KSIExtenderClient extenderClient;
    private PublicationsFileClientAdapter publicationsFileAdapter;
    private KSISignatureFactory signatureFactory;

    /**
     * Creates new instance of {@link KSIServiceImpl}.
     *
     * @param signerClient
     *         - KSI client to be used for signing. May not be null.
     * @param extenderClient
     *         - KSI HTTP client to be used for extending. May not be null.
     * @param publicationsFileAdapter
     *         - KSI HTTP client to be used for fetching the publications file. May not be null.
     */
    public KSIServiceImpl(KSISigningClient signerClient, KSIExtenderClient extenderClient, PublicationsFileClientAdapter publicationsFileAdapter, KSISignatureFactory signatureFactory) throws KSIException {
        if (signerClient == null) {
            throw new KSIException("Invalid input parameter. Singer client can not be null");
        }
        if (extenderClient == null) {
            throw new KSIException("Invalid input parameter. Extender client can not be null");
        }
        if (publicationsFileAdapter == null) {
            throw new KSIException("Invalid input parameter. Publications file client adapter can not be null");
        }
        if (signatureFactory == null) {
            throw new KSIException("Invalid input parameter. KSI signature factory can not be null");
        }
        this.signerClient = signerClient;
        this.extenderClient = extenderClient;
        this.publicationsFileAdapter = publicationsFileAdapter;
        this.signatureFactory = signatureFactory;
    }

    public CreateSignatureFuture sign(DataHash dataHash) throws KSIException {
        Long requestId = generateRequestId();
        AggregationRequestPayload request = new AggregationRequestPayload(dataHash, requestId, DEFAULT_LEVEL);
        ServiceCredentials credentials = signerClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, requestId);
        KSIMessageHeader header = new KSIMessageHeader(credentials.getLoginId(), PduIdentifiers.getInstanceId(), PduIdentifiers.nextMessageId());
        AggregationRequest requestMessage = new AggregationRequest(header, request, credentials.getLoginKey());
        Future<TLVElement> future = signerClient.sign(convert(requestMessage));
        return new CreateSignatureFuture(future, requestContext, signatureFactory);
    }

    public ExtensionRequestFuture extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Long requestId = generateRequestId();
        return extendSignature(new ExtensionRequestPayload(aggregationTime, publicationTime, requestId));
    }

    public PublicationsFile getPublicationsFile() throws KSIException {
        return publicationsFileAdapter.getPublicationsFile();
    }

    protected Long generateRequestId() {
        return Util.nextLong();
    }

    private ExtensionRequestFuture extendSignature(ExtensionRequestPayload extensionRequest)
            throws KSIException {
        ServiceCredentials credentials = extenderClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, extensionRequest.getRequestId());
        KSIMessageHeader header = new KSIMessageHeader(credentials.getLoginId(), PduIdentifiers.getInstanceId(), PduIdentifiers.nextMessageId());
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

    public KSIPublicationsFileClient getPublicationsFileAdapter() {
        return publicationsFileAdapter.getPublicationsFileClient();
    }
}
