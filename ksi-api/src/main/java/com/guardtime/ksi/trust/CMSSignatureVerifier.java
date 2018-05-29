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

package com.guardtime.ksi.trust;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

/**
 * This class is used to verify CMS/PKCS#7 signature.
 */
public class CMSSignatureVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(CMSSignatureVerifier.class);

    private PKITrustStore trustStore;

    static {
        String provider = BouncyCastleProvider.PROVIDER_NAME;
        if (Security.getProvider(provider) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CMSSignatureVerifier(PKITrustStore trustStore) {
        this.trustStore = trustStore;
    }

    @SuppressWarnings("unchecked")
    public void verify(CMSSignature signature) throws CryptoException {
        Store certStore = signature.getSignedDataCertificates();
        SignerInformationStore signerInformationStore = signature.getSignerInformationStore();
        Collection<SignerInformation> signerCollection = signerInformationStore.getSigners();
        if (signerCollection.isEmpty()) {
            throw new InvalidCmsSignatureException("Invalid CMS signature. Signature does not contain SignerInformation element.");
        }
        if (signerCollection.size() != 1) {
            throw new InvalidCmsSignatureException("Invalid CMS signature. Signature contains multiple SignerInformation elements.");
        }
        SignerInformation signerInfo = signerCollection.iterator().next();
        Collection certCollection = certStore.getMatches(signerInfo.getSID());
        Iterator certIterator = certCollection.iterator();

        if (certCollection.isEmpty()) {
            throw new InvalidCmsSignatureException("Invalid CMS signature. Signer certificate collection is empty.");
        }

        X509CertificateHolder certHolder = (X509CertificateHolder) certIterator.next();
        verifyCmsSignerInfo(signerInfo, certHolder);
        if(!trustStore.isTrusted(getCertificate(certHolder), certStore)) {
            throw new InvalidCmsSignatureException("Certificate that was used for signing isn't trusted");
        }
    }

    private void verifyCmsSignerInfo(SignerInformation signerInfo, X509CertificateHolder certHolder) throws InvalidCmsSignatureException {
        try {
            SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(certHolder);
            if (!signerInfo.verify(signerInformationVerifier)) {
                LOGGER.warn("Signer certificate verification failure. Signer info is {}, and certificate subjectDN is {}", signerInfo, certHolder.getSubject());
                throw new InvalidCmsSignatureException("Signature verification failure");
            }
        } catch (CMSException e) {
            throw new InvalidCmsSignatureException("Invalid CMS signature. " + e.getMessage(), e);
        } catch (OperatorCreationException | CertificateException e) {
            throw new InvalidCmsSignatureException("CMS signature validation failed. " + e.getMessage(), e);
        }
    }

    private X509Certificate getCertificate(X509CertificateHolder certHolder) throws InvalidCmsSignatureException {
        try {
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);
        } catch (CertificateException e) {
            throw new InvalidCmsSignatureException("Invalid certificate in CMS signature. " + e.getMessage(), e);
        }
    }


}
