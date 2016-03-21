/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.aggregation;

import static org.testng.Assert.*;

import java.util.List;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class KsiBlockSignerTest {

    private KSI ksi;

    // TODO load from url
    private String pubfileUrl = "http://verify.guardtime.com/ksi-publications.bin";
    private String gatewayUrl = "http://192.168.100.29:2345/gt-signingservice";
    private String extenderUrl = "http://ksigw.test.guardtime.com:8010/gt-extendingservice";

    @BeforeMethod
    public void setUp() throws Exception {
        HttpClientSettings settings = new HttpClientSettings(gatewayUrl, extenderUrl, pubfileUrl, new KSIServiceCredentials("rando", "parool"));
        SimpleHttpClient simpleHttpClient = new SimpleHttpClient(settings);

        this.ksi = new KSIBuilder().setKsiProtocolExtenderClient(simpleHttpClient).
                setKsiProtocolPublicationsFileClient(simpleHttpClient).
                setKsiProtocolSignerClient(simpleHttpClient).
                setPublicationsFileTrustedCertSelector(new X509CertificateSubjectRdnSelector("E=publications@guardtime.com")).
                build();

    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*The request indicated client-side aggregation tree larger than allowed for the client")
    public void testCreateSignatureLargeAggregationTree() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(ksi);
        builder.add(new DataHash(HashAlgorithm.SHA2_256, new byte[32]),255L, new KsiSignatureMetadata("test1"));
        builder.sign();
    }

    @Test
    public void testBlockSigner() throws Exception {
        KsiBlockSigner builder = new KsiBlockSigner(ksi);
        builder.add(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), new KsiSignatureMetadata("test1"));
        builder.add(new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), new KsiSignatureMetadata("test2"));
        builder.add(new DataHash(HashAlgorithm.SHA2_256, new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}), new KsiSignatureMetadata("test3"));

        List<KSISignature> signatures = builder.sign();
        assertNotNull(signatures);
        assertFalse(signatures.isEmpty());
        assertEquals(signatures.size(), 3L);
        for (KSISignature signature : signatures) {
            assertTrue(ksi.verify(signature, new KeyBasedVerificationPolicy()).isOk());
        }
    }

}