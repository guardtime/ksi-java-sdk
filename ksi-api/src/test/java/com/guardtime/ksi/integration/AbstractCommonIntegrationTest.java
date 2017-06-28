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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpClient;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.service.tcp.TCPClient;
import com.guardtime.ksi.service.tcp.TCPClientSettings;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE;
import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.CommonTestUtil.loadFile;
import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE_PASSWORD;
import static com.guardtime.ksi.Resources.PROPERTIES_INTEGRATION_TEST;

public abstract class AbstractCommonIntegrationTest {

    private static final Logger logger = LoggerFactory.getLogger(AbstractCommonIntegrationTest.class);
    protected static final String TEST_GROUP_INTEGRATION = "integration";
    protected static final String KSI_DATA_GROUP_NAME = "ksiDataProvider";
    protected static final String INVALID_SIGNATURES = "INVALID_SIGNATURES";
    protected static final String POLICY_VERIFICATION_SIGNATURES = "POLICY_VERIFICATION_SIGNATURES";
    protected static final String VALID_SIGNATURES = "VALID_SIGNATURES";
    protected static final String DEFAULT_HASH_ALGORITHM = "DEFAULT";
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final String DEFAULT_SIGNING_URL = "http://stamper.guardtime.net/gt-signingservice";
    private static final String DEFAULT_EXTENDER_URL = "http://verifier.guardtime.net/gt-extendingservice";
    private static final String DEFAULT_PUBFILE_URL = "http://verify.guardtime.com/gt-controlpublications.bin";
    protected static final HttpClientSettings FAULTY_HTTP_SETTINGS =
            new HttpClientSettings("http://.", "http://.", "http://.", new KSIServiceCredentials(".", "."));
    protected static String javaKeyStorePath = null;

    protected KSI ksi;
    protected SimpleHttpClient simpleHttpClient;


    @BeforeMethod
    public void setUp() throws Exception {
        this.simpleHttpClient = new SimpleHttpClient(loadHTTPSettings());
        this.ksi = createKsi(simpleHttpClient, simpleHttpClient, simpleHttpClient);
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

        PendingKSIService pendingKSIService = new PendingKSIService();
        ApacheHttpClient failingClient = new ApacheHttpClient(FAULTY_HTTP_SETTINGS);

        List<KSISigningClient> signingClientsForHa = new ArrayList<KSISigningClient>();
        signingClientsForHa.add(failingClient);
        signingClientsForHa.add(simpleHttpClient);
        List<KSISigningService> signingServicesForHa = new ArrayList<KSISigningService>();
        signingServicesForHa.add(pendingKSIService);

        List<KSIExtenderClient> extenderClientsForHa = new ArrayList<KSIExtenderClient>();
        extenderClientsForHa.add(failingClient);
        extenderClientsForHa.add(simpleHttpClient);
        List<KSIExtendingService> extendingServicesForHa = new ArrayList<KSIExtendingService>();
        extendingServicesForHa.add(pendingKSIService);

        HAService haService = new HAService.Builder()
                .addSigningClients(signingClientsForHa)
                .addSigningServices(signingServicesForHa).
                setExtenderClients(extenderClientsForHa)
                .setExtendingServices(extendingServicesForHa)
                .build();

        return new Object[][] {
                new Object[] {createKsi(simpleHttpClient, simpleHttpClient, simpleHttpClient)},
                new Object[] {createKsi(apacheHttpClient, apacheHttpClient, apacheHttpClient)},
                new Object[] {createKsi(apacheHttpClient, tcpClient, apacheHttpClient)},
                new Object[] {createKsi(haService, haService, simpleHttpClient)}
        };
    }

    protected static TCPClientSettings loadTCPSettings() throws IOException {
        Properties prop = new Properties();
        prop.load(load(PROPERTIES_INTEGRATION_TEST));
        String signerIP = prop.getProperty("tcp.signerIP");
        int signerPort = Integer.parseInt(prop.getProperty("tcp.signerPort"));
        int tcpTransactionTimeoutSec = Integer.parseInt(prop.getProperty("tcp.transactionTimeoutSec"));
        String loginId = prop.getProperty("tcp.loginId");
        String loginKey = prop.getProperty("tcp.loginKey");
        ServiceCredentials serviceCredentials = new KSIServiceCredentials(loginId, loginKey);
        return new TCPClientSettings(new InetSocketAddress(signerIP, signerPort), tcpTransactionTimeoutSec,
                serviceCredentials);
    }

    public static HttpClientSettings loadHTTPSettings(PduVersion pduVersion) throws IOException {
        Properties prop = new Properties();
        prop.load(load(PROPERTIES_INTEGRATION_TEST));
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

        HttpClientSettings serviceSettings = new HttpClientSettings(signingUrl, extenderUrl, publicationsFileUrl, credentials,
                pduVersion);
        serviceSettings.getParameters().setConnectionTimeout(DEFAULT_TIMEOUT);
        serviceSettings.getParameters().setReadTimeout(DEFAULT_TIMEOUT);
        return serviceSettings;
    }

    public static HttpClientSettings loadHTTPSettings() throws IOException {
        return loadHTTPSettings(PduVersion.V1);
    }

    protected static Object[] createKsiObject(KSIExtenderClient extenderClient, KSISigningClient signingClient,
                                              KSIPublicationsFileClient publicationsFileClient) throws Exception {
        return new Object[] {createKsi(extenderClient, signingClient, publicationsFileClient)};
    }

    protected static KSI createKsi(KSIExtenderClient extenderClient, KSISigningClient signingClient, KSIPublicationsFileClient
            publicationsFileClient) throws Exception {
        return initKsiBuilder(extenderClient, signingClient, publicationsFileClient).build();
    }

    protected static KSIBuilder initKsiBuilder(KSIExtenderClient extenderClient, KSISigningClient signingClient,
                                               KSIPublicationsFileClient publicationsFileClient) throws Exception {
        return new KSIBuilder().setKsiProtocolExtenderClient(extenderClient).
                setKsiProtocolPublicationsFileClient(publicationsFileClient).
                setKsiProtocolSignerClient(signingClient).
                setPublicationsFilePkiTrustStore(createKeyStore()).
                setPublicationsFileTrustedCertSelector(createCertSelector());
    }

    protected static KSI createKsi(KSIExtendingService extendingService, KSISigningService signingService, KSIPublicationsFileClient
            publicationsFileClient) throws Exception {
        return initKsiBuilder(extendingService, signingService, publicationsFileClient).build();
    }

    protected static KSIBuilder initKsiBuilder(KSIExtendingService extendingService, KSISigningService signingService,
                                               KSIPublicationsFileClient publicationsFileClient) throws Exception {
        return new KSIBuilder().setKsiProtocolExtendingService(extendingService).
                setKsiProtocolPublicationsFileClient(publicationsFileClient).
                setKsiProtocolSigningService(signingService).
                setPublicationsFilePkiTrustStore(createKeyStore()).
                setPublicationsFileTrustedCertSelector(createCertSelector());
    }

    protected static KeyStore createKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(KSI_TRUSTSTORE), KSI_TRUSTSTORE_PASSWORD.toCharArray());
        return trustStore;
    }

    protected static X509CertificateSubjectRdnSelector createCertSelector() throws KSIException {
        return new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
    }

    public VerificationResult verify(KSI ksi, KSIExtendingService extendingService, KSISignature signature, Policy policy) throws
            KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtendingService(extendingService).setPublicationsFile(ksi.getPublicationsFile());
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy, boolean
            extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy,
                                     PublicationData userPublication, boolean extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setUserPublication(userPublication);
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.createVerificationContext(), policy);
    }

    @DataProvider(name = VALID_SIGNATURES)
    public static Object[][] getTestDataAndResultsForValidSignatures() throws Exception {
        try{
            return getTestFilesAndResults("valid-signatures/", "signature-results.csv");
        } catch (Throwable e){
            return new Object[][] {{}};
        }
    }

    @DataProvider(name = INVALID_SIGNATURES)
    public static Object[][] getTestDataAndResultsForInvalidSignatures() throws Exception {
        try{
            return getTestFilesAndResults("invalid-signatures/", "invalid-signature-results.csv");
        } catch (Throwable e){
            return new Object[][] {{}};
        }
    }

    @DataProvider(name = POLICY_VERIFICATION_SIGNATURES)
    public static Object[][] getTestDataAndResultsForPolicyVerificationSignatures() throws Exception {
        try{
            return getTestFilesAndResults("policy-verification-signatures/", "policy-verification-results.csv");
        } catch (Throwable e){
            return new Object[][] {{}};
        }
    }

    private static Object[][] getTestFilesAndResults(String path, String fileName) throws Exception {
        BufferedReader fileReader = null;
        try {
            fileReader = new BufferedReader(new InputStreamReader(new FileInputStream(CommonTestUtil.loadFile(path + fileName))));
            ArrayList<String> lines = new ArrayList<String>();
            String line;
            while ((line = fileReader.readLine()) != null) {
                if (!line.startsWith("#") && line.trim().length() > 17 && !line.contains(IntegrationTestAction.NOT_IMPLEMENTED.getName())) {
                    line = line.replace(";", "; ");
                    lines.add(line);
                }
            }

            int linesCount = lines.size();
            Object[][] data = new Object[linesCount][1];
            SimpleHttpClient httpClient = new SimpleHttpClient(loadHTTPSettings());

            for (int i = 0; i < linesCount; i++) {
                try{
                    data[i] = new Object[]{new IntegrationTestDataHolder(path, lines.get(i).split(";"), httpClient)};
                } catch (Exception e){
                    logger.warn("Error while parsing the following line: '" + lines.get(i) + "' from file: " + fileName);
                    throw e;
                }
            }
            return data;
        } finally {
            if (fileReader != null) {
                fileReader.close();
            }
        }
    }

    protected void testExecution(IntegrationTestDataHolder testData) throws Exception {
        KSISignature signature;
        KSI ksi = testData.getKsi();

        if (testData.getAction().equals(IntegrationTestAction.NOT_IMPLEMENTED)) {
            return;
        }

        if (testData.getAction().equals(IntegrationTestAction.FAIL_AT_PARSING)) {
            try {
                ksi.read(new File(testData.getTestFile()));
                throw new IntegrationTestFailureException("Did not fail at parinsg while expected to. " + testData.toString());
            } catch(KSIException e) {
                return;
            }
        }

        try {
            signature = ksi.read(load(testData.getTestFile()));
        } catch (Exception e) {
            throw new IntegrationTestFailureException("Failure at signature parsing was not expected. " + testData.toString(), e);
        }

        VerificationContext context = testData.getVerificationContext(signature);
        VerificationResult result = ksi.verify(context, testData.getAction().getPolicy());

        if (testData.getErrorCode() == null) {
            Assert.assertTrue(result.isOk(), "Verification result is not OK. " + testData.toString());
        } else {
            if (!(testData.getErrorCode().getCode().equals(result.getErrorCode().getCode()))) {
                throw new IntegrationTestFailureException("Expected verification result error code '" + testData.getErrorCode().getCode() +
                        "' but received '" + result.getErrorCode().getCode() + "'. " + testData.toString());
            } else {
                if (!result.getErrorCode().getMessage().equals(testData.getErrorMessage())) {
                    throw new IntegrationTestFailureException("Expected error message '" + testData.getErrorMessage() +
                            "' but received '" + result.getErrorCode().getMessage() + "'. " + testData.toString());
                }
            }
        }
    }
}
