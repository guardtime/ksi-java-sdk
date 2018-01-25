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

import org.testng.annotations.Test;

public class CMSSignatureTest {

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "CMS signature signed data is null or empty array")
    public void testCreateCMSSignatureWithoutSignedData_ThrowsInvalidCmsSignatureException() throws Exception {
        new CMSSignature(null, new byte[0]);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "CMS signature signed data is null or empty array")
    public void testCreateCMSSignatureWithEmptySignedData_ThrowsInvalidCmsSignatureException() throws Exception {
        new CMSSignature(new byte[0], new byte[0]);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "CMS signature is null or empty array")
    public void testCreateCMSSignatureWithEmptySignatureData_ThrowsInvalidCmsSignatureException() throws Exception {
        new CMSSignature(new byte[1], new byte[0]);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "CMS signature is null or empty array")
    public void testCreateCMSSignatureWithoutCmsSignatureData_ThrowsInvalidCmsSignatureException() throws Exception {
        new CMSSignature(new byte[1], null);
    }

    @Test(expectedExceptions = InvalidCmsSignatureException.class, expectedExceptionsMessageRegExp = "Invalid CMS signature")
    public void testCreateCMSSignatureWithInvalidData_ThrowsInvalidCmsSignatureException() throws Exception {
        new CMSSignature(new byte[32], new byte[128]);

    }


}