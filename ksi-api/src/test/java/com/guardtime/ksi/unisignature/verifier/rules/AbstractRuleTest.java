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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;

import org.mockito.Mockito;

import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;

public abstract class AbstractRuleTest {

    protected VerificationContext build(KSISignature signature) throws Exception {
        return build(signature, null, TestUtil.loadPublicationsFile(PUBLICATIONS_FILE), null, null);
    }

    protected VerificationContext build(KSISignature signature, PublicationData publication) throws Exception {
        return build(signature, null, TestUtil.loadPublicationsFile(PUBLICATIONS_FILE), publication, null);
    }

    protected VerificationContext build(KSISignature signature, PublicationsFile trustStore) throws Exception {
        return build(signature, null, trustStore, null, null);
    }

    protected VerificationContext build(KSISignature signature, DataHash documentHash) throws Exception {
        return build(signature, documentHash, TestUtil.loadPublicationsFile(PUBLICATIONS_FILE), null, null);
    }

    protected VerificationContext build(KSISignature signature, Long level) throws Exception {
        return build(signature, null, TestUtil.loadPublicationsFile(PUBLICATIONS_FILE), null, level);
    }

    protected VerificationContext build(KSISignature signature, DataHash documentHash, PublicationsFile trustStore, PublicationData publication, Long level) {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        KSIExtenderClient mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        Mockito.when(mockedExtenderClient.getPduVersion()).thenReturn(PduVersion.V2);
        builder.setPublicationsFile(trustStore).setExtenderClient(mockedExtenderClient).setUserPublication(publication);
        return builder.setSignature(signature).setDocumentHash(documentHash, level).build();
    }


}
