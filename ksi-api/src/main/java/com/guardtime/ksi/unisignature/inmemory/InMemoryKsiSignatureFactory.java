/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.KSIExtendingClientServiceAdapter;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.RFC3161Record;
import com.guardtime.ksi.unisignature.verifier.KSISignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

import static java.util.Arrays.asList;

/**
 * In memory implementation of the {@link KSISignatureFactory} interface.
 *
 * @see KSISignatureFactory
 */
public final class InMemoryKsiSignatureFactory implements KSISignatureFactory {

    private Policy policy;
    private KSIExtendingService extendingService;
    private PublicationsHandler publicationsHandler;
    private boolean extendingAllowed;

    private boolean verifySignatures = false;

    private KSISignatureComponentFactory signatureComponentFactory;
    private KSISignatureVerifier verifier = new KSISignatureVerifier();

    public InMemoryKsiSignatureFactory() {
    }

    public InMemoryKsiSignatureFactory(KSISignatureComponentFactory signatureComponentFactory) {
        Util.notNull(signatureComponentFactory, "Signature component factory");
        this.signatureComponentFactory = signatureComponentFactory;
    }

    public InMemoryKsiSignatureFactory(ContextAwarePolicy policy, KSISignatureComponentFactory signatureComponentFactory) {
        this(signatureComponentFactory);
        Util.notNull(policy, "Signature verification policy");
        this.policy = policy;
        this.extendingService = policy.getPolicyContext().getExtendingService();
        this.extendingAllowed = policy.getPolicyContext().isExtendingAllowed();
        this.publicationsHandler = policy.getPolicyContext().getPublicationsHandler();
        this.verifySignatures = true;
    }

    @Deprecated
    public InMemoryKsiSignatureFactory(Policy policy, PublicationsFileClientAdapter publicationsFileClientAdapter,
                                       KSIExtendingService extendingService, boolean extendingAllowed,
                                       KSISignatureComponentFactory signatureComponentFactory) {
        this(signatureComponentFactory);
        Util.notNull(policy, "Signature verification policy");
        Util.notNull(publicationsFileClientAdapter, "Publications file client adapter");
        Util.notNull(extendingService, "KSI extending service");
        this.policy = policy;
        this.publicationsHandler = createPublicationsHandler(publicationsFileClientAdapter);
        this.extendingService = extendingService;
        this.extendingAllowed = extendingAllowed;
        this.verifySignatures = true;
    }

    @Deprecated
    public InMemoryKsiSignatureFactory(Policy policy, PublicationsFileClientAdapter publicationsFileClientAdapter,
                                       KSIExtenderClient extenderClient, boolean extendingAllowed,
                                       KSISignatureComponentFactory signatureComponentFactory) {
        this(policy, publicationsFileClientAdapter, new KSIExtendingClientServiceAdapter(extenderClient), extendingAllowed, signatureComponentFactory);
    }

    @Deprecated
    public InMemoryKsiSignatureFactory(Policy policy, PublicationsFileClientAdapter publicationsFileClientAdapter,
                                       KSIExtenderClient extenderClient, boolean extendingAllowed,  PduFactory pduFactory,
                                       KSISignatureComponentFactory signatureComponentFactory) {
        this(policy, publicationsFileClientAdapter, new KSIExtendingClientServiceAdapter(extenderClient), extendingAllowed, signatureComponentFactory);
    }

    public KSISignature createSignature(InputStream input) throws KSIException {
        TLVInputStream tlvInput = new TLVInputStream(input);
        try {
            return createSignature(tlvInput.readElement(), extendingAllowed);
        } catch (IOException e) {
            throw new KSIException("Reading signature data from input stream failed", e);
        } finally {
            Util.closeQuietly(tlvInput);
        }
    }

    public KSISignature createSignature(TLVElement element, DataHash inputHash) throws KSIException {
        return createSignature(element, extendingAllowed, inputHash, 0L);
    }

    public KSISignature createSignature(TLVElement element, DataHash inputHash, long level) throws KSIException {
        return createSignature(element, extendingAllowed, inputHash, level);
    }

    public KSISignature createSignature(List<AggregationHashChain> aggregationHashChains,
                                        CalendarHashChain calendarChain, CalendarAuthenticationRecord calendarAuthenticationRecord,
                                        PublicationRecord signaturePublicationRecord, RFC3161Record rfc3161Record) throws KSIException {

        TLVElement root = new TLVElement(false, false, InMemoryKsiSignature.ELEMENT_TYPE);
        for (AggregationHashChain chain : aggregationHashChains) {
            addTlvStructure(root, (TLVStructure) chain);
        }
        if (calendarChain != null) {
            addTlvStructure(root, (TLVStructure) calendarChain);
            if (signaturePublicationRecord != null) {
                addTlvStructure(root, (TLVStructure) signaturePublicationRecord);
            } else {
                addTlvStructure(root, (TLVStructure) calendarAuthenticationRecord);
            }
        }
        addTlvStructure(root, (TLVStructure) rfc3161Record);
        return createSignature(root, extendingAllowed);
    }

    private KSISignature createSignature(TLVElement element, boolean extendingAllowed) throws KSIException {
        return createSignature(element, extendingAllowed, null, 0L);
    }

    private KSISignature createSignature(TLVElement element, boolean extendingAllowed, DataHash inputHash, long level) throws KSIException {
        InMemoryKsiSignature signature = new InMemoryKsiSignature(element);
        if (level > 0) {
            AggregationHashChain firstChain = signature.getAggregationHashChains()[0];
            LinkedList<AggregationChainLink> links = new LinkedList<>(firstChain.getChainLinks());
            AggregationChainLink link = createLinkWithLevelCorrection(firstChain.getChainLinks().get(0), level);
            links.set(0, link);

            LinkedList<Long> chainIndex = new LinkedList<>(firstChain.getChainIndex());
            List<AggregationHashChain> aggregationHashChains = new LinkedList<>(asList(signature.getAggregationHashChains()));
            AggregationHashChain aggregationHashChain = signatureComponentFactory.createAggregationHashChain(inputHash,
                    firstChain.getAggregationTime(), chainIndex, links, firstChain.getAggregationAlgorithm());
            aggregationHashChains.set(0, aggregationHashChain);

            signature = (InMemoryKsiSignature) createSignature(aggregationHashChains, signature.getCalendarHashChain(),
                    signature.getCalendarAuthenticationRecord(), signature.getPublicationRecord(), signature.getRfc3161Record());
        }
        if (verifySignatures) {
            VerificationContextBuilder builder = new VerificationContextBuilder();
            builder.setSignature(signature).setExtendingService(extendingService)
                    .setPublicationsFile(getPublicationsFile(publicationsHandler))
                    .setExtendingAllowed(extendingAllowed);
            if (inputHash != null) {
                builder.setDocumentHash(inputHash, level);
            }
            VerificationContext context = builder.build();
            context.setKsiSignatureComponentFactory(signatureComponentFactory);

            VerificationResult result = verifier.verify(context, policy);
            if (!result.isOk()) {
                throw new InvalidSignatureContentException(signature, result);
            }
        }
        return signature;
    }

    private PublicationsFile getPublicationsFile(PublicationsHandler handler) throws KSIException {
        if (handler == null) {
            return null;
        }
        return handler.getPublicationsFile();
    }

    private PublicationsHandler createPublicationsHandler(final PublicationsFileClientAdapter clientAdapter) {
        return new PublicationsHandler() {
            public PublicationsFile getPublicationsFile() throws KSIException {
                return clientAdapter.getPublicationsFile();
            }
        };
    }

    private void addTlvStructure(TLVElement root, TLVStructure structure) throws KSIException {
        if (structure != null) {
            root.addChildElement(structure.getRootElement());
        }
    }

    private AggregationChainLink createLinkWithLevelCorrection(AggregationChainLink link, long level) throws KSIException {
        if (link.isLeft()) {
            return signatureComponentFactory.createLeftAggregationChainLink(link, level);
        } else {
            return signatureComponentFactory.createRightAggregationChainLink(link, level);
        }
    }
}
