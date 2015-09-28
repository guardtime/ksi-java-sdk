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

package com.guardtime.ksi.trust;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.util.X509CertUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.testng.Assert;
import org.testng.annotations.Test;

public class X509CertificateSubjectRdnSelectorTest {

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter.At least one RDN must be present")
    public void testCreateSelectorWithMissingRdnArray_ThrowsKSIException() throws Exception {
        new X509CertificateSubjectRdnSelector((RDN[]) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter.At least one RDN must be present")
    public void testCreateSelectorWithEmptyRdnArray_ThrowsKSIException() throws Exception {
        new X509CertificateSubjectRdnSelector(new RDN[0]);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. RDN string must be present")
    public void testCreateSelectorWithMissingRdnString_ThrowsKSIException() throws Exception {
        new X509CertificateSubjectRdnSelector((String) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. RDN string must be present")
    public void testCreateSelectorWithEmptyRdnString_ThrowsKSIException() throws Exception {
        new X509CertificateSubjectRdnSelector("");
    }

    @Test
    public void testX509CertificateMatches_Ok() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testX509CertificateMatchesUsingLongRdnType_Ok() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("EMAILADDRESS=publications@guardtime.com");
        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testX509CertificateMatchesUsingDifferentRdnValues_Ok() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("EMAILADDRESS=publications@guardtime.com,L=Tallinn, C=EE, C=EE");
        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testX509CertificateDoesNotMatch_Ok() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("E=publications2@guardtime.com");
        Assert.assertFalse(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testX509CertificateDoesNotMatchUsingMultipleRdnValues_Ok() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com,E=publications2@guardtime.com");
        Assert.assertFalse(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

}