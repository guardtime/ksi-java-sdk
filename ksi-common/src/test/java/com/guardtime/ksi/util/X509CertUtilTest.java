/*
 * Copyright 2013-2017 Guardtime, Inc.
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

package com.guardtime.ksi.util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.InputStream;

public class X509CertUtilTest {

    @Test
    public void testConvertByteArrayToX509Certificate_Ok() throws Exception {
        InputStream cert = Thread.currentThread().getContextClassLoader().getResourceAsStream("server.crt");
        Assert.assertNotNull(X509CertUtil.toCert(Util.toByteArray(cert)));
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Input bytes can not be null")
    public void testConvertNullArrayToX509Certificate_ThrowsIllegalArgumentException() {
        X509CertUtil.toCert(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Certificate generation failed")
    public void testConvertInvalidByteArrayToX509Certificate_ThrowsIllegalArgumentException() {
        X509CertUtil.toCert(new byte[32]);
    }

}
