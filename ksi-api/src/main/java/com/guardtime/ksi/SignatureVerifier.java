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
                .setExtenderClient(c.getExtenderClient())
                .setExtendingAllowed(c.isExtendingAllowed())
                .setPublicationsFile(c.getPublicationsHandler() != null ? c.getPublicationsHandler().getPublicationsFile() : null)
                .setSignature(signature)
                .setUserPublication(c.getUserPublication())
                .build();
        context.setKsiSignatureComponentFactory(new InMemoryKsiSignatureComponentFactory());

        return verifier.verify(context, policy);
    }
}
