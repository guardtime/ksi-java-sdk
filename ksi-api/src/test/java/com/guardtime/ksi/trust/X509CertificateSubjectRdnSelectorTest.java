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

package com.guardtime.ksi.trust;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.util.X509CertUtil;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class X509CertificateSubjectRdnSelectorTest {

    private static final AttributeTypeAndValue EMAIL = new AttributeTypeAndValue(BCStyle.EmailAddress, new DERIA5String("publications@guardtime.com"));
    private static final AttributeTypeAndValue EMAIL_INVALID = new AttributeTypeAndValue(BCStyle.EmailAddress, new DERIA5String("pub@kala.com"));

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

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Multi-valued certificate constraints aren't supported")
    public void testMultiValuedRdn_ThrowsKSIException() throws Exception {
        new X509CertificateSubjectRdnSelector("CN=Test+E=publications@guardtime.com");
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

    @Test
    public void testMultipleDifferentRdnWithSameOid() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new TestX509CertificateSubjectRdnSelector(
                "E=publications@guardtime.com", new AttributeTypeAndValue[] {EMAIL_INVALID, EMAIL});

        Assert.assertFalse(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testMultipleSameRdnWithSameOid() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new TestX509CertificateSubjectRdnSelector(
                "E=publications@guardtime.com", new AttributeTypeAndValue[] {EMAIL, EMAIL});

        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testMultiValuedRdnInCertificate() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new TestX509CertificateSubjectRdnSelector(
                "E=publications@guardtime.com", new AttributeTypeAndValue[] {EMAIL, EMAIL}, true);

        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testMultiValuedRdnContainingInvalidEmail() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new TestX509CertificateSubjectRdnSelector(
                "E=publications@guardtime.com", new AttributeTypeAndValue[] {EMAIL_INVALID, EMAIL}, true);

        Assert.assertFalse(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    @Test
    public void testDifferentAsn1Encodings() throws Exception {
        X509CertificateSubjectRdnSelector certSelector = new TestX509CertificateSubjectRdnSelector("E=publications@guardtime.com",
                new AttributeTypeAndValue[]{new AttributeTypeAndValue(BCStyle.EmailAddress, new DERPrintableString("publications@guardtime.com"))}, true);

        Assert.assertTrue(certSelector.match(X509CertUtil.toCert(TestUtil.loadBytes("server.crt"))));
    }

    static class TestX509CertificateSubjectRdnSelector extends  X509CertificateSubjectRdnSelector {

        private final AttributeTypeAndValue[] typeValues;
        private boolean multiValue;

        public TestX509CertificateSubjectRdnSelector(String rdnString, AttributeTypeAndValue[] typeValues, boolean multiValue) throws KSIException {
            super(rdnString);
            this.typeValues = typeValues;
            this.multiValue = multiValue;
        }

        public TestX509CertificateSubjectRdnSelector(String rdnString, AttributeTypeAndValue[] typeValues) throws KSIException {
            this(rdnString, typeValues, false);
        }

        @Override
        X500Name getX500SubjectName(X509Certificate cert) throws CertificateEncodingException {

            X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());
            if(multiValue) {
                nameBuilder.addMultiValuedRDN(typeValues);
            } else {
                for (AttributeTypeAndValue typeValue : typeValues) {
                    nameBuilder.addRDN(typeValue);

                }
            }
            return nameBuilder.build();
        }
    }
}
