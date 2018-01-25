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

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents CMS/PKCS#7 signature
 */
public class CMSSignature {

    private static final Logger LOGGER = LoggerFactory.getLogger(CMSSignature.class);

    private final SignerInformationStore signerInformationStore;
    private final Store signedDataCertificates;

    public CMSSignature(byte[] signedData, byte[] cmsSignature) throws InvalidCmsSignatureException {
        try {
            if (signedData == null || signedData.length < 1) {
                throw new InvalidCmsSignatureException("CMS signature signed data is null or empty array");
            }
            if (cmsSignature == null || cmsSignature.length < 1) {
                throw new InvalidCmsSignatureException("CMS signature is null or empty array");
            }
            CMSProcessableByteArray cmsProcessable = new CMSProcessableByteArray(signedData);
            CMSSignedData cmsSignedData = new CMSSignedData(cmsProcessable, cmsSignature);
            this.signerInformationStore = cmsSignedData.getSignerInfos();
            this.signedDataCertificates = cmsSignedData.getCertificates();
            LOGGER.debug("CMS signature contains {} signer information elements", signerInformationStore.size());
        } catch (CMSException e) {
            throw new InvalidCmsSignatureException("Invalid CMS signature", e);
        }
    }

    public Store getSignedDataCertificates() {
        return signedDataCertificates;
    }

    public SignerInformationStore getSignerInformationStore() {
        return signerInformationStore;
    }

}
