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
import com.guardtime.ksi.util.Util;
import com.guardtime.ksi.util.X509CertUtil;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class JKSTrustStoreTest {

    @Test(expectedExceptions = InvalidKeyStoreException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Key store must be present")
    public void testCreateJKSTrustStore_ThrowsInvalidKeyStoreException() throws Exception {
        new JKSTrustStore((KeyStore) null, null);
    }

    @Test(expectedExceptions = InvalidKeyStoreException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Key store path must be present")
    public void testCreateJKSTrustStoreWithoutKeyStorePath_ThrowsInvalidKeyStoreException() throws Exception {
        new JKSTrustStore((String) null, null);
    }

    @Test(expectedExceptions = InvalidKeyStoreException.class, expectedExceptionsMessageRegExp = "Loading java key store with path my_file failed")
    public void testCreateJKSTrustStoreFromFileThatDoesNotExist_ThrowsInvalidKeyStoreException() throws Exception {
        new JKSTrustStore("my_file", "password".toCharArray(), null);
    }

    @Test(expectedExceptions = CryptoException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Certificate can not be null")
    public void testCheckIfCertificateIsTrustedUsingInvalidInput_ThrowsCryptoException() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore("truststore.jks", null);
        trustStore.isTrusted(null, null);
    }

    @Test
    public void testCheckIfCertificateIsTrusted_Ok() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore("truststore.jks", null);
        Assert.assertTrue(trustStore.isTrusted((X509Certificate) X509CertUtil.toCert(Util.toByteArray(TestUtil.load("server.crt"))), null));
    }

    @Test
    public void testCheckIfCertificateIsTrustedWithEmail_Ok() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore("truststore.jks", null, new X509CertificateSubjectRdnSelector("E=publications@guardtime.com"));
        Assert.assertTrue(trustStore.isTrusted((X509Certificate) X509CertUtil.toCert(Util.toByteArray(TestUtil.load("server.crt"))), null));
    }

    @Test(expectedExceptions = InvalidCertificateException.class, expectedExceptionsMessageRegExp = "Invalid certificated subject with subjectDN EMAILADDRESS=publications@guardtime.com.*")
    public void testCheckIfCertificateIsTrustedWithInvalidEmail_ThrowsInvalidCertificateSubjectException() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore("truststore.jks", null, new X509CertificateSubjectRdnSelector("E=invalid_publications@guardtime.com"));
        Assert.assertTrue(trustStore.isTrusted((X509Certificate) X509CertUtil.toCert(Util.toByteArray(TestUtil.load("server.crt"))), null));
    }

    @Test
    public void testCheckUntrustedCertificate_Ok() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore("truststore.jks", null);
        Assert.assertFalse(trustStore.isTrusted((X509Certificate) X509CertUtil.toCert(Util.toByteArray(TestUtil.load("cert.crt"))), null));
    }

    @Test(expectedExceptions = CryptoException.class, expectedExceptionsMessageRegExp = "General security error occurred. Uninitialized keystore")
    public void testUseUninitializedKeyStore_ThrowsCryptoException() throws Exception {
        JKSTrustStore trustStore = new JKSTrustStore(KeyStore.getInstance("JKS"), null);
        trustStore.isTrusted((X509Certificate) X509CertUtil.toCert(Util.toByteArray(TestUtil.load("server.crt"))), null);
    }
}