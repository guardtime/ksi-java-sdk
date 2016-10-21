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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.multisignature.KSIMultiSignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.util.Base16;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import static org.testng.Assert.*;

public class FileBasedMultiSignatureFactoryTest {

    private FileBasedMultiSignatureFactory factory;

    @BeforeMethod
    public void setUp() throws Exception {
        KSI mockedKsi = Mockito.mock(KSI.class);
        factory = new FileBasedMultiSignatureFactory(mockedKsi, new InMemoryKsiSignatureFactory());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI can not be null")
    public void testCreateFactoryUsingInvalidInputParameters_ThrowsKSIException() throws Exception {
        new FileBasedMultiSignatureFactory(null, new InMemoryKsiSignatureFactory());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI uni signature factory must be present")
    public void testCreateFactoryWithoutUniSignatureFactory_ThrowsKSIException() throws Exception {
        new FileBasedMultiSignatureFactory(Mockito.mock(KSI.class), null);
    }

    @Test
    public void testCreateNewMultiSignature_Ok() throws Exception {
        File tempFile = createTempFile();
        KSIMultiSignature multiSignature = factory.create(new FileBasedMultiSignatureConfigurationParameters(tempFile));
        assertNotNull(multiSignature);
        assertEquals(multiSignature.getUsedHashAlgorithms().length, 0);
    }

    @Test
    public void testAddUniSignaturesToEmptyContainer_Ok() throws Exception {
        File tempFile = createTempFile();
        KSIMultiSignature multiSignature = factory.create(new FileBasedMultiSignatureConfigurationParameters(tempFile));
        multiSignature.add(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig"));
        assertNotNull(multiSignature);
        assertEquals(multiSignature.getUsedHashAlgorithms().length, 1);
    }

    @Test
    public void testAddAndRemoveUniSignature_Ok() throws Exception {
        File tempFile = createTempFile();
        FileBasedMultiSignature multiSignature = factory.create(new FileBasedMultiSignatureConfigurationParameters(tempFile));
        multiSignature.add(TestUtil.loadSignature("testdata.txt.2015-01.tlv"));
        multiSignature.remove(new DataHash(HashAlgorithm.SHA2_256, Base16.decode("5466E3CBA14A843A5E93B78E3D6AB8D3491EDCAC7E06431CE1A7F49828C340C3]")));
        assertNotNull(multiSignature);
        assertEquals(multiSignature.getUsedHashAlgorithms().length, 0);
        assertEquals(multiSignature.getAggregationHashChains().size(), 0);
        assertEquals(multiSignature.getCalendarAuthenticationRecords().size(), 0);
        assertEquals(multiSignature.getCalendarHashChains().size(), 0);
        assertEquals(multiSignature.getSignaturePublicationRecords().size(), 0);
        assertEquals(multiSignature.getRfc3161Records().size(), 0);
    }

    @Test
    public void testReadEmptyContainer_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = factory.create(new FileBasedMultiSignatureConfigurationParameters(TestUtil.loadFile("multi-signature/multi-signature-empty.tlv")));
        assertNotNull(multiSignature);
        assertEquals(multiSignature.getUsedHashAlgorithms().length, 0);
    }

    @Test
    public void testReadContainerWithMultipleUniSignatures_Ok() throws Exception {
        FileBasedMultiSignature multiSignature = factory.create(new FileBasedMultiSignatureConfigurationParameters(TestUtil.loadFile("multi-signature/multi-signature-with-five-uni-signatures-ok.ksi")));
        assertTrue(multiSignature.getAggregationHashChains().size() > 0);
        assertTrue(multiSignature.getCalendarAuthenticationRecords().size() > 0);
        assertTrue(multiSignature.getCalendarHashChains().size() > 0);
        assertTrue(multiSignature.getSignaturePublicationRecords().size() > 0);
        assertTrue(multiSignature.getRfc3161Records().size() > 0);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. File based multi signature configuration parameter must be present")
    public void testCreateFactoryWithoutConfigurationParameter_ThrowsKSIException() throws Exception {
        factory.create(null);
    }

    public File createTempFile() throws IOException {
        File tempFile = File.createTempFile(UUID.randomUUID().toString(), ".ksi");
        tempFile.deleteOnExit();
        return tempFile;
    }

}
