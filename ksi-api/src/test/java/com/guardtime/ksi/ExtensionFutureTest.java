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
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_DATA_HASH_MISMATCH;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA;
import static com.guardtime.ksi.Resources.CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class ExtensionFutureTest {

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_originalCalendarHashChainHasMoreRightLinks() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_MISSING).getResult();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_originalCalendarHashChainHasLessRightLinks() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_EXTRA).getResult();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Right links of signature calendar hash chain and extended calendar hash chain do not match")
    public void testCalendarHashChainsMismatch_rightLinkHashDifferent() throws Exception {
        createExtensionFuture(SIGNATURE_2017_03_14, CALENDAR_HASH_CHAIN_RIGHT_LINK_DATA_HASH_MISMATCH).getResult();
    }

    private ExtensionFuture createExtensionFuture(String signatureFileName, String extendedCalendarChainFileName) throws Exception {
        KSISignature signature = loadSignature(signatureFileName);
        TLVElement calendarChainTlvElement = loadTlv(extendedCalendarChainFileName);

        Future<ExtensionResponse> future = Mockito.mock(Future.class);
        ExtensionResponse extensionResponse = Mockito.mock(ExtensionResponse.class);
        Mockito.when(future.getResult()).thenReturn(extensionResponse);
        Mockito.when(extensionResponse.getCalendarHashChain()).thenReturn(calendarChainTlvElement);
        PublicationRecord publicationRecord = Mockito.mock(PublicationRecord.class);

        return new ExtensionFuture(future, publicationRecord, signature, new InMemoryKsiSignatureComponentFactory(), new InMemoryKsiSignatureFactory());
    }
}