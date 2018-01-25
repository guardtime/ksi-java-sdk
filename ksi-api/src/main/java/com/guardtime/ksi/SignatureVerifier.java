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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.verifier.KSISignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.PolicyContext;
import com.guardtime.ksi.util.Util;

/**
 * Obtaining {@link Verifier} object(s) and using it to verify KSI signatures.
 */

public class SignatureVerifier implements Verifier {

    private KSISignatureVerifier verifier = new KSISignatureVerifier();

    public VerificationResult verify(KSISignature signature, ContextAwarePolicy policy) throws KSIException {
        return verify(signature, null, null, policy);
    }

    public VerificationResult verify(KSISignature signature, DataHash documentHash, ContextAwarePolicy policy)
            throws KSIException {
        return verify(signature, documentHash, null, policy);
    }

    public VerificationResult verify(KSISignature signature, DataHash documentHash, Long level, ContextAwarePolicy policy)
            throws KSIException {
        Util.notNull(signature, "Signature");
        Util.notNull(policy, "Policy");
        PolicyContext c = policy.getPolicyContext();
        VerificationContext context = new VerificationContextBuilder()
                .setDocumentHash(documentHash, level)
                .setExtendingService(c.getExtendingService())
                .setExtendingAllowed(c.isExtendingAllowed())
                .setPublicationsFile(c.getPublicationsHandler() != null ? c.getPublicationsHandler().getPublicationsFile() : null)
                .setSignature(signature)
                .setUserPublication(c.getUserPublication())
                .build();
        context.setKsiSignatureComponentFactory(new InMemoryKsiSignatureComponentFactory());

        return verifier.verify(context, policy);
    }
}
