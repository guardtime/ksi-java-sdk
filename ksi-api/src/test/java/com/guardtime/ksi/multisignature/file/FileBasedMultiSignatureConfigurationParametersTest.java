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

import com.guardtime.ksi.exceptions.KSIException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;

import static org.testng.Assert.assertNotNull;

public class FileBasedMultiSignatureConfigurationParametersTest {

    @Test
    public void testCreateFileBasedMultiSignatureConfigurationParameters_Ok() throws Exception {
        File mockedFile = Mockito.mock(File.class);
        FileBasedMultiSignatureConfigurationParameters conf = new FileBasedMultiSignatureConfigurationParameters(mockedFile);
        assertNotNull(conf);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "File must be present")
    public void testCreateFileBasedMultiSignatureConfigurationParametersWithInvalidInput_ThrowsKSIException() throws Exception {
        new FileBasedMultiSignatureConfigurationParameters(null);
    }

}