/*
 * Copyright 2013-2016 Guardtime, Inc.
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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.tlv.TLVStructure;
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
import java.util.List;

/**
 * In memory implementation of the {@link KSISignatureFactory} interface.
 *
 * @see KSISignatureFactory
 */
public final class InMemoryKsiSignatureFactory implements KSISignatureFactory {

    private Policy policy;
    private KSIExtenderClient extenderClient;
    private PublicationsHandler publicationsHandler;
    private boolean extendingAllowed;

    private boolean verifySignatures = false;

    private KSISignatureComponentFactory signatureComponentFactory;
    private KSISignatureVerifier verifier = new KSISignatureVerifier();

    public InMemoryKsiSignatureFactory() {
    }

    public InMemoryKsiSignatureFactory(ContextAwarePolicy policy, KSISignatureComponentFactory signatureComponentFactory) {
        Util.notNull(policy, "Signature verification policy");
        Util.notNull(policy.getPolicyContext(), "Policy Context");
        Util.notNull(signatureComponentFactory, "Signature component factory");
        this.policy = policy;
        this.extenderClient = policy.getPolicyContext().getExtenderClient();
        this.extendingAllowed = policy.getPolicyContext().isExtendingAllowed();
        this.publicationsHandler = policy.getPolicyContext().getPublicationsHandler();
        this.signatureComponentFactory = signatureComponentFactory;
        this.verifySignatures = true;
    }

    @Deprecated
    public InMemoryKsiSignatureFactory(Policy policy, PublicationsFileClientAdapter publicationsFileClientAdapter,
                                       KSIExtenderClient extenderClient, boolean extendingAllowed,
                                       KSISignatureComponentFactory signatureComponentFactory) {
        Util.notNull(policy, "Signature verification policy");
        Util.notNull(publicationsFileClientAdapter, "Publications file client adapter");
        Util.notNull(extenderClient, "KSI extender client");
        this.policy = policy;
        this.publicationsHandler = createPublicationsHandler(publicationsFileClientAdapter);
        this.extenderClient = extenderClient;
        this.extendingAllowed = extendingAllowed;
        this.signatureComponentFactory = signatureComponentFactory;
        this.verifySignatures = true;
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
        return createSignature(element, extendingAllowed, inputHash);
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
        return createSignature(element, extendingAllowed, null);
    }

    private KSISignature createSignature(TLVElement element, boolean extendingAllowed, DataHash inputHash) throws KSIException {
        InMemoryKsiSignature signature = new InMemoryKsiSignature(element);
        if (verifySignatures) {
            VerificationContextBuilder builder = new VerificationContextBuilder()
                    .setSignature(signature)
                    .setExtenderClient(extenderClient)
                    .setPublicationsFile(getPublicationsFile(publicationsHandler))
                    .setExtendingAllowed(extendingAllowed);
            if (inputHash != null) {
                builder.setDocumentHash(inputHash);
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
}
