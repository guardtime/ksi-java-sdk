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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.*;
import com.guardtime.ksi.unisignature.verifier.KSISignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
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
    private PublicationsFileClientAdapter publicationsFileClientAdapter;
    private boolean extendingAllowed;

    private boolean verifySignatures = false;

    private KSISignatureVerifier verifier = new KSISignatureVerifier();

    public InMemoryKsiSignatureFactory(Policy policy, PublicationsFileClientAdapter publicationsFileClientAdapter, KSIExtenderClient extenderClient, boolean extendingAllowed) {
        Util.notNull(policy, "Signature verification policy");
        Util.notNull(publicationsFileClientAdapter, "Publications file client adapter");
        Util.notNull(extenderClient, "KSI extender client");
        this.policy = policy;
        this.publicationsFileClientAdapter = publicationsFileClientAdapter;
        this.extenderClient = extenderClient;
        this.extendingAllowed = extendingAllowed;
        this.verifySignatures = true;
    }

    public InMemoryKsiSignatureFactory() {
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
        return createSignature(root, false);
    }

    private KSISignature createSignature(TLVElement element, boolean extendingAllowed) throws KSIException {
        return createSignature(element, extendingAllowed, null);
    }

    private KSISignature createSignature(TLVElement element, boolean extendingAllowed, DataHash inputHash) throws KSIException {
        InMemoryKsiSignature signature = new InMemoryKsiSignature(element);
        if (verifySignatures) {
            VerificationContextBuilder builder = new VerificationContextBuilder();
            builder.setSignature(signature).setExtenderClient(extenderClient)
                    .setPublicationsFile(publicationsFileClientAdapter.getPublicationsFile())
                    .setExtendingAllowed(extendingAllowed);
            if (inputHash != null) {
                builder.setDocumentHash(inputHash);
            }
            VerificationResult result = verifier.verify(builder.createVerificationContext(), policy);
            if (!result.isOk()) {
                throw new InvalidSignatureContentException(signature, result);
            }
        }
        return signature;
    }

    private void addTlvStructure(TLVElement root, TLVStructure structure) throws KSIException {
        if (structure != null) {
            root.addChildElement(structure.getRootElement());
        }
    }
}
