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

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.Extender;
import com.guardtime.ksi.ExtenderBuilder;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.PublicationsHandlerBuilder;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings;
import com.guardtime.ksi.service.client.http.HTTPConnectionParameters;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.client.http.HttpSettings;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpExtenderClient;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpPublicationsFileClient;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpSigningClient;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPublicationsFileClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpSigningClient;
import com.guardtime.ksi.service.tcp.TCPClient;
import com.guardtime.ksi.service.tcp.TCPClientSettings;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;

import com.guardtime.ksi.util.Util;

import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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
import java.util.Objects;
import java.util.Properties;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.CommonTestUtil.loadFile;
import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE;
import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE_PASSWORD;
import static com.guardtime.ksi.Resources.PROPERTIES_INTEGRATION_TEST;
import static com.guardtime.ksi.TestUtil.calculateHash;

public abstract class AbstractCommonIntegrationTest {

    private static final Logger logger = LoggerFactory.getLogger(AbstractCommonIntegrationTest.class);
    protected static final String TEST_GROUP_INTEGRATION = "integration";
    protected static final String TEST_GROUP_TCP_INTEGRATION = "TcpIntegration";
    protected static final String DEFAULT_HASH_ALGORITHM = "DEFAULT";
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final String DEFAULT_PUBFILE_URL = "http://verify.guardtime.com/gt-controlpublications.bin";
    protected static final HttpClientSettings FAULTY_HTTP_SETTINGS =
            new HttpClientSettings("http://.", "http://.", "http://.", new KSIServiceCredentials(".", "."));
    protected static String javaKeyStorePath = null;

    protected KSI ksi;
    protected SimpleHttpSigningClient signerClient;
    protected SimpleHttpExtenderClient extenderClient;
    protected SimpleHttpPublicationsFileClient publicationsFileClient;

    protected static CredentialsAwareHttpSettings signingSettings;
    protected static CredentialsAwareHttpSettings extenderSettings;
    protected static HttpSettings publicationsFileSettings;
    protected static Properties properties;

    @BeforeClass
    protected void setUp() throws Exception {
        properties = loadProperties();
        javaKeyStorePath = loadJavaKeyStorePath();
        signingSettings = loadSignerSettings();
        extenderSettings = loadExtenderSettings();
        publicationsFileSettings = loadPublicationsFileSettings();
        signerClient = new SimpleHttpSigningClient(signingSettings);
        extenderClient = new SimpleHttpExtenderClient(extenderSettings);
        publicationsFileClient = new SimpleHttpPublicationsFileClient(publicationsFileSettings);
        ksi = createKsi(extenderClient, signerClient, publicationsFileClient);
    }

    @AfterClass
    protected void tearDown() throws Exception {
        if (ksi != null) ksi.close();
        if (signerClient != null) signerClient.close();
        if (extenderClient != null) extenderClient.close();
        if (publicationsFileClient != null) publicationsFileClient.close();
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


    @Deprecated
    public static HttpClientSettings loadHTTPSettings(PduVersion pduVersion){
        Properties props = loadProperties();
        String extenderUrl = getProperty(props, "extenderUrl");
        String publicationsFileUrl = props.getProperty("pubfileUrl", DEFAULT_PUBFILE_URL);
        String signingUrl = getProperty(props, "gatewayUrl");
        String loginKey = getProperty(props, "loginKey");
        String loginId = getProperty(props, "loginId");

        ServiceCredentials credentials = new KSIServiceCredentials(loginId, loginKey);

        if (props.containsKey("javaKeyStorePath")) {
            javaKeyStorePath = getProperty(props, "javaKeyStorePath");
        }

        HttpClientSettings serviceSettings = new HttpClientSettings(signingUrl, extenderUrl, publicationsFileUrl, credentials,
                pduVersion);
        serviceSettings.getParameters().setConnectionTimeout(DEFAULT_TIMEOUT);
        serviceSettings.getParameters().setReadTimeout(DEFAULT_TIMEOUT);
        return serviceSettings;
    }


    protected static TCPClientSettings loadTCPSigningSettings() {
        Properties props = loadProperties();
        String signerIP = getProperty(props, "tcp.signerIP");
        int signerPort = Integer.parseInt(getProperty(props, "tcp.signerPort"));
        int tcpTransactionTimeoutSec = Integer.parseInt(getProperty(props, "tcp.transactionTimeoutSec"));
        String loginId = getProperty(props, "tcp.signerLoginId", "tcp.loginId");
        String loginKey = getProperty(props, "tcp.signerLoginKey", "tcp.loginKey");
        ServiceCredentials serviceCredentials = new KSIServiceCredentials(loginId, loginKey);
        return new TCPClientSettings(new InetSocketAddress(signerIP, signerPort), tcpTransactionTimeoutSec,
                serviceCredentials);
    }

    protected static TCPClientSettings loadTCPExtendingSettings(){
        Properties props = loadProperties();
        String extenderIp = getProperty(props, "tcp.extenderIP");
        int extenderPort = Integer.parseInt(getProperty(props, "tcp.extenderPort"));
        int tcpTransactionTimeoutSec = Integer.parseInt(getProperty(props, "tcp.transactionTimeoutSec"));
        String loginId = getProperty(props, "tcp.extenderLoginId", "tcp.loginId");
        String loginKey = getProperty(props, "tcp.extenderLoginKey", "tcp.loginKey");
        ServiceCredentials serviceCredentials = new KSIServiceCredentials(loginId, loginKey);
        return new TCPClientSettings(new InetSocketAddress(extenderIp, extenderPort), tcpTransactionTimeoutSec,
                serviceCredentials);
    }

    public static HttpSettings loadPublicationsFileSettings() {
        if (publicationsFileSettings == null) {
            Properties props = loadProperties();
            HTTPConnectionParameters params = new HTTPConnectionParameters(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT);
            publicationsFileSettings = new HttpSettings(getProperty(props, "pubfileUrl"), params);
        }
        return publicationsFileSettings;
    }

    public static CredentialsAwareHttpSettings loadSignerSettings() {
        if (signingSettings == null) {
            signingSettings = loadSignerSettings(PduVersion.V2);
        }
        return signingSettings;
    }

    public static CredentialsAwareHttpSettings loadExtenderSettings() {
        if (extenderSettings == null) {
            extenderSettings = loadExtenderSettings(PduVersion.V2);
        }
        return extenderSettings;
    }

    public static CredentialsAwareHttpSettings loadSignerSettings(PduVersion pduVersion) {
        Properties props = loadProperties();
        ServiceCredentials credentials = new KSIServiceCredentials(
                getProperty(props, "signerLoginId", "loginId"),
                getProperty(props, "signerLoginKey", "loginKey"));
        return loadSettings(getProperty(props, "signerUrl", "gatewayUrl"), credentials, pduVersion);
    }

    public static CredentialsAwareHttpSettings loadExtenderSettings(PduVersion pduVersion) {
        Properties props = loadProperties();

        ServiceCredentials credentials = new KSIServiceCredentials(
                getProperty(props, "extenderLoginId", "loginId"),
                getProperty(props, "extenderLoginKey", "loginKey"));

        return loadSettings(getProperty(props, "extenderUrl"), credentials,  pduVersion);
    }

    public static CredentialsAwareHttpSettings loadSettings(String url, ServiceCredentials credentials, PduVersion pduVersion) {
        HTTPConnectionParameters params = new HTTPConnectionParameters(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT);
        CredentialsAwareHttpSettings settings = new CredentialsAwareHttpSettings(url, credentials, params);
        settings.setPduVersion(pduVersion);
        return settings;
    }

    private String loadJavaKeyStorePath() {
        Properties props = loadProperties();
        if (javaKeyStorePath == null && props.containsKey("javaKeyStorePath")) {
            javaKeyStorePath = getProperty(props, "javaKeyStorePath");
        }
        return javaKeyStorePath;
    }

    private static Properties loadProperties() {
        if (properties == null) {
            properties = new Properties();
            try {
                properties.load(load(PROPERTIES_INTEGRATION_TEST));
            } catch (IOException e) {
                throw new RuntimeException(PROPERTIES_INTEGRATION_TEST
                        + " file must be added to folder 'ksi-api/src/test/resources' for running the integration tests");
            }
        }
        return properties;
    }

    private static String getProperty(Properties props, String preferredKey, String alternativeKey) {
        String value = null;
        if (props.containsKey(preferredKey)) {
            value = getProperty(props, preferredKey);
        } else if (props.containsKey(alternativeKey)) {
            value = getProperty(props, alternativeKey);
        } else {
            throw new NullPointerException(preferredKey + " is missing in " + PROPERTIES_INTEGRATION_TEST);
        }
        return value;
    }

    private static String getProperty(Properties prop, String key) {
        return Objects.requireNonNull(prop.getProperty(key), key + " is missing in " + PROPERTIES_INTEGRATION_TEST);
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

    protected PublicationsHandler getPublicationsHandler(KSIPublicationsFileClient publicationsFileClient) throws Exception {
        return new PublicationsHandlerBuilder().setKsiProtocolPublicationsFileClient(publicationsFileClient)
                .setPublicationsFileCacheExpirationTime(10000L)
                .setPublicationsFilePkiTrustStore(createKeyStore())
                .setPublicationsFileCertificateConstraints(createCertSelector()).build();
    }

    protected Extender getExtender(KSIExtendingService extendingService, KSIPublicationsFileClient publicationsFileClient) throws Exception {
        return new ExtenderBuilder()
                .setExtendingService(extendingService)
                .setPublicationsHandler(getPublicationsHandler(publicationsFileClient)).build();
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
        return ksi.verify(builder.build(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy, boolean
            extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.build(), policy);
    }

    public VerificationResult verify(KSI ksi, KSIExtenderClient extenderClient, KSISignature signature, Policy policy,
                                     PublicationData userPublication, boolean extendingAllowed) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(ksi.getPublicationsFile());
        builder.setUserPublication(userPublication);
        builder.setExtendingAllowed(extendingAllowed);
        return ksi.verify(builder.build(), policy);
    }

    protected static KSISigningService mockSigningService(final String responseFile, final ServiceCredentials credentials) throws Exception {
        KSISigningService mockedSigningService = Mockito.mock(KSISigningService.class);

        final Future<TLVElement> mockedFuture = Mockito.mock(Future.class);
        Mockito.when(mockedFuture.isFinished()).thenReturn(Boolean.TRUE);
        final TLVElement responseTLV = TLVElement.create(IOUtils.toByteArray(load(responseFile)));
        Mockito.when(mockedFuture.getResult()).thenReturn(responseTLV);

        Mockito.when(mockedSigningService.sign(Mockito.any(DataHash.class), Mockito.any
                (long.class))).then(new Answer<Future>() {
            public Future<AggregationResponse> answer(InvocationOnMock invocationOnMock) throws Throwable {
                DataHash dataHash = (DataHash) invocationOnMock.getArguments()[0];
                long level = (long) invocationOnMock.getArguments()[1];

                PduFactory factory = new PduV2Factory();
                KSIRequestContext context = RequestContextFactory.DEFAULT_FACTORY.createContext();
                AggregationRequest request = factory.createAggregationRequest(context, credentials, dataHash, level);
                ByteArrayInputStream bais = new ByteArrayInputStream(request.toByteArray());
                TLVElement requestElement = TLVElement.create(Util.toByteArray(bais));
                //Set header
                responseTLV.getFirstChildElement(0x1).setContent(requestElement.getFirstChildElement(0x1).getEncoded());
                //Set Request ID
                responseTLV.getFirstChildElement(0x2).getFirstChildElement(0x1).setLongContent(
                        requestElement.getFirstChildElement(0x2).getFirstChildElement(0x1).getDecodedLong()
                );
                //Set Input hash
                responseTLV.getFirstChildElement(0x2).getFirstChildElement(0x801).getFirstChildElement(0x5).setDataHashContent(dataHash);
                //Update HMAC
                responseTLV.getFirstChildElement(0x1F).setDataHashContent(
                        calculateHash(
                                responseTLV,
                                responseTLV.getFirstChildElement(0x1F).getDecodedDataHash().getAlgorithm(),
                                credentials.getLoginKey()
                        )
                );
                return new AggregationResponseFuture(mockedFuture, context, credentials, factory);
            }
        });

        return mockedSigningService;
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
            } catch (KSIException e) {
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
