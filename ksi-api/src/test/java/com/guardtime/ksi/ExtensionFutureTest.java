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

import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_EXTENDED_FROM_SIG_WITH_AGGR_CHAIN_ONLY;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_DATA_HASH_MISMATCH;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class ExtensionFutureTest {

    @Test(expectedExceptions = InconsistentCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_originalCalendarHashChainHasMoreRightLinks() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING).getResult();
    }

    @Test(expectedExceptions = InconsistentCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_originalCalendarHashChainHasLessRightLinks() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA).getResult();
    }

    @Test(expectedExceptions = InconsistentCalendarHashChainException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_rightLinkHashDifferent() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_DATA_HASH_MISMATCH).getResult();
    }


    @Test
    public void testSignatureExtension_noCalendarChainInSignature() throws Exception {
        KSISignature signature = createExtensionFuture(SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS,
                CALENDAR_HASH_CHAIN_EXTENDED_FROM_SIG_WITH_AGGR_CHAIN_ONLY).getResult();
        Assert.assertTrue(signature.isExtended());
    }

    private ExtensionFuture createExtensionFuture(String signatureFileName, String extendedCalendarChainFileName) throws Exception {
        KSISignature signature = loadSignature(signatureFileName);
        TLVElement calendarChainTlvElement = loadTlv(extendedCalendarChainFileName);

        InMemoryKsiSignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
        InMemoryKsiSignatureFactory signatureFactory =
                new InMemoryKsiSignatureFactory(ContextAwarePolicyAdapter.createInternalPolicy(), signatureComponentFactory);

        String publicationString = "AAAAAA-C2VG3Y-AANAMA-FULJ3X-CMWLPB-F5O2BA-7Y6UE5-VOJKPQ-OV2VFQ-W3SXJM-JIDMWY-4PDBN2";
        PublicationRecord publicationRecord = signatureComponentFactory.createPublicationRecord(
                new PublicationData(publicationString), null, null);

        Future<ExtensionResponse> future = Mockito.mock(Future.class);
        ExtensionResponse extensionResponse = Mockito.mock(ExtensionResponse.class);
        Mockito.when(future.getResult()).thenReturn(extensionResponse);
        Mockito.when(extensionResponse.getCalendarHashChain()).thenReturn(calendarChainTlvElement);

        return new ExtensionFuture(future, publicationRecord, signature, signatureComponentFactory, signatureFactory);
    }
}