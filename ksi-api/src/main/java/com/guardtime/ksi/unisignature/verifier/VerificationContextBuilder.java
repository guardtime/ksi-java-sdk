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

package com.guardtime.ksi.unisignature.verifier;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;

/**
 * This class is used to createSignature {@link VerificationContext} instances.
 */
public class VerificationContextBuilder {

    private PublicationsFile publicationsFile;
    private KSISignature signature;
    private PublicationData userPublication;
    private boolean extendingAllowed;
    private KSIExtenderClient extenderClient;
    private DataHash documentHash;

    /**
     * Used to set the KSI signature that is verified.
     *
     * @param signature
     *         signature to verify.
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setSignature(KSISignature signature) {
        this.signature = signature;
        return this;
    }

    /**
     * Used to set the publications file that is used by verification process
     *
     * @param publicationsFile
     *         instance of publications file. may be null.
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setPublicationsFile(PublicationsFile publicationsFile) {
        this.publicationsFile = publicationsFile;
        return this;
    }

    /**
     * Used to set the user publication (e.g from newspaper). Used by {@link com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy}.
     *
     * @param userPublication
     *         instance of publication data. may be null.
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setUserPublication(PublicationData userPublication) {
        this.userPublication = userPublication;
        return this;
    }

    /**
     * If true then extending is allowed when verifying signature. Does not affect {@link
     * com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy} policy.
     *
     * @param extendingAllowed
     *         true if extending is allowed, false otherwise
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setExtendingAllowed(boolean extendingAllowed) {
        this.extendingAllowed = extendingAllowed;
        return this;
    }

    /**
     * Used to set the {@link KSIExtenderClient} to be used to extend signature.
     *
     * @param extenderClient
     *         instance of extender client
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setExtenderClient(KSIExtenderClient extenderClient) {
        this.extenderClient = extenderClient;
        return this;
    }

    /**
     * Used to set the hash of the original document. If present then this hash must equal to signature input hash.
     *
     * @param documentHash
     *         document hash
     * @return instance of {@link VerificationContextBuilder}
     */
    public VerificationContextBuilder setDocumentHash(DataHash documentHash) {
        this.documentHash = documentHash;
        return this;
    }

    /**
     * Builds the verification context.
     *
     * @return instance of verification context
     * @throws KSIException
     *         when error occurs (e.g mandatory parameters aren't present)
     */
    public final VerificationContext createVerificationContext() throws KSIException {
        if (signature == null) {
            throw new KSIException("Failed to createSignature verification context. Signature must be present.");
        }
        if (extenderClient == null) {
            throw new KSIException("Failed to createSignature verification context. KSI extender client must be present.");
        }
        if (publicationsFile == null) {
            throw new KSIException("Failed to createSignature verification context. PublicationsFile must be present.");
        }
        return new KSIVerificationContext(publicationsFile, signature, userPublication, extendingAllowed, extenderClient, documentHash);
    }

}