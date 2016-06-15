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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.*;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.service.tcp.TCPClient;
import com.guardtime.ksi.service.tcp.TCPClientSettings;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.util.Util;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;

import java.io.*;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Properties;

import static com.guardtime.ksi.TestUtil.*;

public abstract class AbstractCommonIntegrationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractCommonIntegrationTest.class);
    protected static final String TEST_GROUP_INTEGRATION = "integration";
    protected static final String KSI_DATA_GROUP_NAME = "ksiDataProvider";
    protected static final String INTERNAL_VERIFICATION_DATA_PROVIDER = "INTERNAL_VERIFICATION_DATA_PROVIDER";
    protected static final String CALENDAR_BASED_VERIFICATION_DATA_PROVIDER = "CALENDAR_BASED_VERIFICATION_DATA_PROVIDER";
    protected static final String KEY_BASED_VERIFICATION_DATA_PROVIDER = "KEY_BASED_VERIFICATION_DATA_PROVIDER";
    protected static final String TLV_PARSER_VERIFICATION_DATA_PROVIDER = "TLV_PARSER_VERIFICATION_DATA_PROVIDER";
    protected static final String EXTENDER_RESPONSES_DATA_PROVIDER = "EXTENDER_RESPONSES_DATA_PROVIDER";
    protected static final String DEFAULT_HASH_ALGORITHM = "DEFAULT";
    protected static final String INPUT_FILE = "infile";
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final String DEFAULT_SIGNING_URL = "http://stamper.guardtime.net/gt-signingservice";
    private static final String DEFAULT_EXTENDER_URL = "http://verifier.guardtime.net/gt-extendingservice";
    private static final String DEFAULT_PUBFILE_URL = "http://verify.guardtime.com/gt-controlpublications.bin";
    protected static String javaKeyStorePath = null;

    protected KSI ksi;
    protected SimpleHttpClient simpleHttpClient;
    protected ServiceCredentials serviceCredentials;

    @BeforeMethod
    public void setUp() throws Exception {
        this.simpleHttpClient = new SimpleHttpClient(loadHTTPSettings());
        this.serviceCredentials = simpleHttpClient.getServiceCredentials();
        this.ksi = new KSIBuilder().setKsiProtocolExtenderClient(simpleHttpClient).
                setKsiProtocolPublicationsFileClient(simpleHttpClient).
                setKsiProtocolSignerClient(simpleHttpClient).
                setPublicationsFileTrustedCertSelector(createCertSelector()).
                build();
    }

    public static DataHash getFileHash(String fileName, String name) throws Exception {
        return getFileHash(fileName, HashAlgorithm.getByName(name));
    }

    public static DataHash getFileHash(String fileName, HashAlgorithm algorithm) throws Exception {
        DataHasher dataHasher = new DataHasher(algorithm);
        dataHasher.addData(loadFile(fileName));
        return dataHasher.getHash();
    }

    public static DataHash getFileHash(String fileName) throws Exception {
        return getFileHash(fileName, DEFAULT_HASH_ALGORITHM);
    }

    @DataProvider(name = KSI_DATA_GROUP_NAME)
    public static Object[][] transportProtocols() throws Exception {
        HttpClientSettings httpSettings = loadHTTPSettings();
        SimpleHttpClient simpleHttpClient = new SimpleHttpClient(httpSettings);
        ApacheHttpClient apacheHttpClient = new ApacheHttpClient(httpSettings);
        TCPClientSettings tcpSettings = loadTCPSettings();
        KSISigningClient tcpClient = new TCPClient(tcpSettings);

        return new Object[][]{
                new Object[]{createKsi(simpleHttpClient, simpleHttpClient, simpleHttpClient), simpleHttpClient},
                new Object[]{createKsi(apacheHttpClient, apacheHttpClient, apacheHttpClient), apacheHttpClient},
                new Object[]{createKsi(apacheHttpClient, tcpClient, apacheHttpClient), apacheHttpClient}
        };
    }

    protected static TCPClientSettings loadTCPSettings() throws IOException {
        Properties prop = new Properties();
        prop.load(load("integrationtest.properties"));
        String signerIP = prop.getProperty("tcp.signerIP");
        int tcpThreadPoolSize = Integer.parseInt(prop.getProperty("tcp.maxParallelTransactions"));
        int signerPort = Integer.parseInt(prop.getProperty("tcp.signerPort"));
        int tcpTransactionTimeoutSec = Integer.parseInt(prop.getProperty("tcp.transactionTimeoutSec"));
        String loginId = prop.getProperty("tcp.loginId");
        String loginKey = prop.getProperty("tcp.loginKey");
        ServiceCredentials serviceCredentials = new KSIServiceCredentials(loginId, loginKey);
        return new TCPClientSettings(new InetSocketAddress(signerIP, signerPort), tcpTransactionTimeoutSec, tcpThreadPoolSize, serviceCredentials);
    }

    public static HttpClientSettings loadHTTPSettings() throws IOException {
        Properties prop = new Properties();
        prop.load(load("integrationtest.properties"));
        String extenderUrl = prop.getProperty("extenderUrl", DEFAULT_EXTENDER_URL);
        String publicationsFileUrl = prop.getProperty("pubfileUrl", DEFAULT_PUBFILE_URL);
        String signingUrl = prop.getProperty("gatewayUrl", DEFAULT_SIGNING_URL);
        String loginKey = prop.getProperty("loginKey", null);
        String loginId = prop.getProperty("loginId", null);

        ServiceCredentials credentials = TestUtil.CREDENTIALS_ANONYMOUS;
        if (loginKey != null && loginId != null) {
            credentials = new KSIServiceCredentials(loginId, loginKey);
        }

        if (prop.containsKey("javaKeyStorePath")) {
            javaKeyStorePath = prop.getProperty("javaKeyStorePath");
        }

        HttpClientSettings serviceSettings = new HttpClientSettings(signingUrl, extenderUrl, publicationsFileUrl, credentials);
        serviceSettings.getParameters().setConnectionTimeout(DEFAULT_TIMEOUT);
        serviceSettings.getParameters().setReadTimeout(DEFAULT_TIMEOUT);
        return serviceSettings;
    }

    protected static Object[] createKsiObject(KSIExtenderClient extenderClient, KSISigningClient signingClient, KSIPublicationsFileClient publicationsFileClient) throws KSIException {
        return new Object[]{createKsi(extenderClient, signingClient, publicationsFileClient)};
    }

    protected static KSI createKsi(KSIExtenderClient extenderClient, KSISigningClient signingClient, KSIPublicationsFileClient publicationsFileClient) throws KSIException {
        return new KSIBuilder().setKsiProtocolExtenderClient(extenderClient).
                setKsiProtocolPublicationsFileClient(publicationsFileClient).
                setKsiProtocolSignerClient(signingClient).
                setPublicationsFileTrustedCertSelector(createCertSelector()).build();
    }

    protected static X509CertificateSubjectRdnSelector createCertSelector() throws KSIException {
        return new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy, boolean extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy, PublicationData userPublication, boolean extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setUserPublication(userPublication);
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    protected void mockExtenderResponseCalendarHashCain(String responseCalendarChainFile, KSIExtenderClient mockedExtenderClient) throws Exception {
        final Future<TLVElement> mockedFuture = Mockito.mock(Future.class);
        Mockito.when(mockedFuture.isFinished()).thenReturn(Boolean.TRUE);
        Mockito.when(mockedExtenderClient.getServiceCredentials()).thenReturn(serviceCredentials);
        final TLVElement responseTLV = TLVElement.createFromBytes(TestUtil.loadBytes("extension/extension-response-ok-request-id-4321.tlv"));
        Mockito.when(mockedFuture.getResult()).thenReturn(responseTLV);
        final TLVElement calendarChain = TLVElement.createFromBytes(TestUtil.loadBytes(responseCalendarChainFile));

        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).then(new Answer<Future>() {
            public Future answer(InvocationOnMock invocationOnMock) throws Throwable {
                InputStream input = (InputStream) invocationOnMock.getArguments()[0];
                TLVElement tlvElement = TLVElement.createFromBytes(Util.toByteArray(input));
                TLVElement payload = responseTLV.getFirstChildElement(0x302);
                payload.getFirstChildElement(0x01).setLongContent(tlvElement.getFirstChildElement(0x301).getFirstChildElement(0x01).getDecodedLong());

                payload.replace(payload.getFirstChildElement(CalendarHashChain.ELEMENT_TYPE), calendarChain);
                responseTLV.getFirstChildElement(0x1F).setDataHashContent(calculateHash(serviceCredentials.getLoginKey(), responseTLV.getFirstChildElement(0x01), payload));
                return mockedFuture;
            }
        });
    }

    private DataHash calculateHash(byte[] key, TLVElement... elements) throws Exception {
        HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
        return new DataHash(algorithm, Util.calculateHMAC(getContent(elements), key, algorithm.getName()));
    }

    private byte[] getContent(TLVElement[] elements) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (TLVElement element : elements) {
            out.write(element.getEncoded());
        }
        return out.toByteArray();
    }

    @DataProvider(name = INTERNAL_VERIFICATION_DATA_PROVIDER)
    public static Object[][] getTestFilesAndResultsForInternalVerification() throws Exception {
        return getTestFilesAndResults(CommonTestUtil.loadFile("internal_verification_test_files_and_expected_results.txt"));
    }

    @DataProvider(name = CALENDAR_BASED_VERIFICATION_DATA_PROVIDER)
    public static Object[][] getTestFilesAndResultsForCalendarBasedVerification() throws Exception {
        return getTestFilesAndResults(CommonTestUtil.loadFile("calendar_based_verification_test_files_and_expected_results.txt"));
    }

    @DataProvider(name = KEY_BASED_VERIFICATION_DATA_PROVIDER)
    public static Object[][] getTestFilesAndResultsForKeyBasedVerification() throws Exception {
        return getTestFilesAndResults(CommonTestUtil.loadFile("key_based_verification_test_files_and_expected_results.txt"));
    }

    @DataProvider(name = TLV_PARSER_VERIFICATION_DATA_PROVIDER)
    public static Object[][] getTestFilesAndResultsForTlvParserVerification() throws Exception {
        return getTestFilesAndResults(CommonTestUtil.loadFile("tlv_parser_verification_test_files_and_expected_results.txt"));
    }

    @DataProvider(name = EXTENDER_RESPONSES_DATA_PROVIDER)
    public static Object[][] getExtenderResponsesAndResultsForTlvParserVerification() throws Exception {
        return getTestFilesAndResults(CommonTestUtil.loadFile("tlv_parser_verification_test_extender_responses_and_expected_results.txt"));
    }

    private static Object[][] getTestFilesAndResults(File inFile) throws Exception {
        BufferedReader fileReader = null;
        try {
            fileReader = new BufferedReader(new InputStreamReader(new FileInputStream(inFile)));
            ArrayList<String> lines = new ArrayList<String>();
            String line;
            while ((line = fileReader.readLine()) != null) {
                if (!line.startsWith("#")) {
                    lines.add(line);
                }
            }

            int linesCount = lines.size();
            Object[][] data = new Object[linesCount][1];
            SimpleHttpClient httpClient = new SimpleHttpClient(loadHTTPSettings());

            for (int i = 0; i < linesCount; i++) {
                data[i] = new Object[]{new DataHolderForIntegrationTests(lines.get(i).split(":"), httpClient)};
            }
            return data;
        } finally {
            if(fileReader != null) {
                fileReader.close();
            }
        }

    }

    protected void testExecution(DataHolderForIntegrationTests testData, Policy policy) throws Exception {
        try {
            LOGGER.info("Running test with the following data: " + testData.getTestDataInformation() + "; Policy: " + policy.getName());
            KSISignature signature = loadSignature(testData.getTestFile());
            Assert.assertTrue(testData.getExpectException(), testData.getTestFile() + " supposed to fail with class " + testData.getExpectedExceptionClass() + " exception.");
            VerificationResult result = verify(ksi, testData.getHttpClient(), signature, policy);
            VerificationErrorCode errorCode = result.getErrorCode();
            if (testData.getExpectFailureWithErrorCode()) {
                Assert.assertTrue(result.isOk(), "Result is not OK, error code: " + errorCode);
                Assert.assertNull(result.getErrorCode(), "Error code is not null, error code: " + errorCode);
            } else {
                Assert.assertFalse(result.isOk(), "Result is not NOK, error code: " + errorCode);
                Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.valueOf(testData.getExpectedFailureCode()));
            }
        } catch (Exception e) {
            if (!(e.getMessage().contains(testData.getExpectedExceptionMessage()) &&
                    e.getClass().toString().contains(testData.getExpectedExceptionClass()) &&
                    !testData.getExpectException() && testData.getExpectedFailureCode().equals(" "))) {
                LOGGER.warn("Test failed with " + testData.getTestDataInformation() + "; Policy: " + policy.getName());
                throw e;
            }
        }
    }
}
