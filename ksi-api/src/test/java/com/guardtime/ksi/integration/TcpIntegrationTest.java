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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpPublicationsFileClient;
import com.guardtime.ksi.service.tcp.ExtenderTCPClient;
import com.guardtime.ksi.service.tcp.KSITCPTransactionException;
import com.guardtime.ksi.service.tcp.SigningTCPClient;
import com.guardtime.ksi.service.tcp.TCPClientSettings;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.guardtime.ksi.Resources.INPUT_FILE;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class TcpIntegrationTest extends AbstractCommonIntegrationTest {

    private static final String KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER = "ksiInvalidCredentialsTCPDataProvider";
    private static final String VALID_HASH_ALGORITHMS_DATA_PROVIDER = "VALID_HASH_ALGORITHMS";

    private static final String EMPTY_LOGIN_ID = "";
    private static final String SHORT_LOGIN_ID = "a"; //Length: 1
    private static final String LONG_LOGIN_ID = "HcGE1poIT09hI9S80WzDE65qzbRIitlSGXfrABGp3yBhYvsaE13a" +
            "t0kLJZtj0jc2SrsUCH1iIF3XlUiB2mEiETh82NC4p5WGzAcM1Y" +
            "sTZEaWSs27aHfIq49jzQRs3LejGVfqNijVsb86RBZWKlZpYIc4" +
            "alyPaM4eymvMn6Di8VIhEvUpJqfay5REg016NWopK0WfpU6ZcA" +
            "EX9g4vu0futr1JlGz5UoUAhS0AHRIz62ucr0k88aZI9YHlvJ6Y"; //Length: 252

    private static ApacheHttpPublicationsFileClient pubFileClient;

    private static KSISigningClient tcpSigningClient;
    private static KSIExtenderClient tcpExtenderClient;

    private static KSI emptyKsi = null;
    private static KSI shortKsi = null;
    private static KSI longKsi = null;

    @BeforeMethod
    public void setUp() throws Exception {
        tcpSigningClient = new SigningTCPClient(loadTCPSigningSettings());
        tcpExtenderClient = new ExtenderTCPClient(loadTCPExtendingSettings());
        pubFileClient = new ApacheHttpPublicationsFileClient(loadPublicationsFileSettings());
        this.ksi = createKsi(tcpExtenderClient, tcpSigningClient, pubFileClient);
    }

    @AfterMethod
    public void closeClients() throws Exception {
        if (pubFileClient != null) pubFileClient.close();
        if (tcpSigningClient != null) tcpSigningClient.close();
        if (tcpExtenderClient != null) tcpExtenderClient.close();
        if (ksi != null) ksi.close();
    }

    @AfterTest
    public void testTearDown() throws IOException {
        if (emptyKsi != null) emptyKsi.close();
        if (shortKsi != null) shortKsi.close();
        if (longKsi != null) longKsi.close();
    }

    @Test(dataProvider = VALID_HASH_ALGORITHMS_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION)
    public void testTCPStressingUsingDifferentHashAlgorithms(HashAlgorithm algorithm) throws Exception {
        VerificationResult result = signAndVerify(algorithm);
        Thread.sleep(400);
        VerificationResult result2 = signAndVerify(algorithm);
        Assert.assertTrue(result.isOk());
        Assert.assertTrue(result2.isOk());
    }

    @Test(dataProvider = KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = {KSITCPTransactionException.class, IllegalArgumentException.class})
    public void testTCPIncorrectLoginCredentialsWithSHA2_256(KSI ksi) throws Exception {
        ksi.sign(getFileHash(INPUT_FILE, HashAlgorithm.SHA2_256));
    }

    @Test(dataProvider = KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = {KSITCPTransactionException.class, IllegalArgumentException.class})
    public void testTCPIncorrectLoginCredentialsWithSHA2_384(KSI ksi) throws Exception {
        ksi.sign(getFileHash(INPUT_FILE, HashAlgorithm.SHA2_384));
    }

    @Test(dataProvider = KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = {KSITCPTransactionException.class, IllegalArgumentException.class})
    public void testTCPIncorrectLoginCredentialsWithSHA2_512(KSI ksi) throws Exception {
        ksi.sign(getFileHash(INPUT_FILE,HashAlgorithm.SHA2_512));
    }

    @Test(dataProvider = KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = {KSITCPTransactionException.class, IllegalArgumentException.class})
    public void testTCPIncorrectLoginCredentialsWithRIPEMD_160(KSI ksi) throws Exception {
        ksi.sign(getFileHash(INPUT_FILE, HashAlgorithm.RIPEMD_160));
    }

    @Test(dataProvider = VALID_HASH_ALGORITHMS_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Hash size.* does not match .* size.*")
    public void testTcpWithShortHash(HashAlgorithm hashAlgorithm) throws Exception {
        int hashLength = hashAlgorithm.getLength();
        ksi.sign(new DataHash(hashAlgorithm, new byte[hashLength - 1]));
    }

    @Test(dataProvider = VALID_HASH_ALGORITHMS_DATA_PROVIDER, groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Hash size.* does not match .* size.*")
    public void testTcpWithLongHash(HashAlgorithm hashAlgorithm) throws Exception {
        int hashLength = hashAlgorithm.getLength();
        ksi.sign(new DataHash(hashAlgorithm, new byte[hashLength + 1]));
    }

    @Test (groups = TEST_GROUP_INTEGRATION
            , expectedExceptions = IllegalStateException.class, expectedExceptionsMessageRegExp = "The connector is being disposed.")
    public void tcpSigningClientSettingsConnector() throws Exception {
        try (KSI tcpKsi = createKsi(tcpExtenderClient, tcpSigningClient, pubFileClient)) {
            tcpSigningClient.close();
            tcpKsi.sign(new byte[0]);
        }
    }

    @Test (groups = TEST_GROUP_INTEGRATION)
    public void testTcpExtenderClient_OK() throws Exception {
        try (KSI tcpKsi = createKsi(tcpExtenderClient, tcpSigningClient, pubFileClient)) {
            tcpKsi.extend(loadSignature(SIGNATURE_2014_06_02));
        }
    }

    @Test (groups = TEST_GROUP_INTEGRATION,
            expectedExceptions = IllegalStateException.class, expectedExceptionsMessageRegExp = "The connector is being disposed.")
    public void testTcpExtenderClientSettingsConnector() throws Exception {
        try (KSI tcpKsi = createKsi(tcpExtenderClient, tcpSigningClient, pubFileClient)) {
            tcpExtenderClient.close();
            tcpKsi.extend(loadSignature(SIGNATURE_2014_06_02));
        }
    }

    @Test (groups = TEST_GROUP_INTEGRATION)
    public void testClosingOneTcpClientDoesNotCloseTheOther() throws Exception {
        try (KSI tcpKsi = createKsi(tcpExtenderClient, tcpSigningClient, pubFileClient)) {
            tcpSigningClient.close();
            tcpKsi.extend(loadSignature(SIGNATURE_2014_06_02));
        }
    }

    private VerificationResult signAndVerify(HashAlgorithm algorithm) throws Exception {
        DataHash fileHash = getFileHash(INPUT_FILE, algorithm);
        KSISignature sig = ksi.sign(fileHash);
        return ksi.verify(TestUtil.buildContext(sig, ksi, tcpExtenderClient, fileHash), new KeyBasedVerificationPolicy());
    }

    @DataProvider(name = VALID_HASH_ALGORITHMS_DATA_PROVIDER)
    private static Object[][] hashAlgorithmProvider() {
        List<HashAlgorithm> hashAlgorithms = new ArrayList<>();
        HashAlgorithm[] allAlgorithms = HashAlgorithm.values();
        Date currentDate = new Date();
        for (HashAlgorithm algorithm : allAlgorithms) {
            if (HashAlgorithm.Status.NORMAL.equals(algorithm.getStatus()) && !algorithm.isDeprecated(currentDate)) {
                hashAlgorithms.add(algorithm);
            }
        }
        Object[][] data = new Object[hashAlgorithms.size()][1];
        for (int i = 0; i < hashAlgorithms.size(); i++) {
            data[i] = new Object[]{hashAlgorithms.get(i)};
        }
        return data;
    }

    @DataProvider(name = KSI_INVALID_CREDENTIALS_TCP_DATA_PROVIDER)
    private static Object[][] credentialsTransportProtocols() throws Exception {
        TCPClientSettings emptyTcpSettings = loadTCPSettings(EMPTY_LOGIN_ID, EMPTY_LOGIN_ID);
        TCPClientSettings shortTcpSettings = loadTCPSettings(SHORT_LOGIN_ID, SHORT_LOGIN_ID);
        TCPClientSettings longTcpSettings = loadTCPSettings(LONG_LOGIN_ID, LONG_LOGIN_ID);
        KSISigningClient emptyTcpClient = new SigningTCPClient(emptyTcpSettings);
        KSISigningClient shortTcpClient = new SigningTCPClient(shortTcpSettings);
        KSISigningClient longTcpClient = new SigningTCPClient(longTcpSettings);

        emptyKsi = createKsi(tcpExtenderClient, emptyTcpClient, pubFileClient);
        shortKsi = createKsi(tcpExtenderClient, shortTcpClient, pubFileClient);
        longKsi = createKsi(tcpExtenderClient, longTcpClient, pubFileClient);

        return new Object[][]{
                new Object[] {emptyKsi},
                new Object[] {shortKsi},
                new Object[] {longKsi}
        };
    }

    private static TCPClientSettings loadTCPSettings(String loginId, String loginKey) throws IOException {
        TCPClientSettings settings = loadTCPSigningSettings();
        int tcpTransactionTimeoutSec = 1;
        ServiceCredentials serviceCredentials = new KSIServiceCredentials(loginId, loginKey);
        return new TCPClientSettings(settings.getEndpoint(), tcpTransactionTimeoutSec, serviceCredentials);
    }

}
