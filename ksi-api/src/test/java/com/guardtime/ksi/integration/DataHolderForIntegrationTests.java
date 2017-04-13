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

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.DefaultPduIdentifierProvider;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPostRequestFuture;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.trust.JKSTrustStore;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.verifier.AlwaysSuccessfulPolicy;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.util.Base16;
import com.guardtime.ksi.util.Util;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.integration.AbstractCommonIntegrationTest.createCertSelector;
import static com.guardtime.ksi.integration.AbstractCommonIntegrationTest.createKeyStore;
import static com.guardtime.ksi.integration.AbstractCommonIntegrationTest.loadHTTPSettings;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class DataHolderForIntegrationTests {

    private String testFile;
    private final IntegrationTestAction action;
    private final VerificationErrorCode errorCode;
    private final String errorMessage;
    private final DataHash inputHash;
    private final DataHash chcInputHash;
    private final DataHash chchOutputHash;
    private final Date registrationTime;
    private final Date aggregationTime;
    private final Date publicationTime;
    private final PublicationData userPublication;
    private final boolean extendingPermitted;
    private final String responseFile;
    private final String publicationsFile;

    private KSIExtenderClient extenderClient;
    private KSI ksi;
    private final HttpClientSettings settings;
    private KSIExtenderClient httpClient;

    public DataHolderForIntegrationTests(String testFilePath, String[] inputData, KSIExtenderClient httpClient) throws KSIException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        notNull(inputData, "Input data");
        for (int i = 0; i < inputData.length; i++) {
            inputData[i] = inputData[i].trim();
        }

        notNull(httpClient, "Extender http client");
        extenderClient = httpClient;

        notEmpty(inputData[0], "Test file");
        if (testFilePath != null && !testFilePath.trim().isEmpty()) {
            testFile = testFilePath + inputData[0];
            responseFile = inputData[12].isEmpty() ? null : testFilePath + inputData[12];
            publicationsFile = inputData[13].isEmpty() ? null : testFilePath + inputData[13];
        } else {
            testFile = inputData[0];
            responseFile = inputData[12].isEmpty() ? null : inputData[12];
            publicationsFile = inputData[13].isEmpty() ? null : inputData[13];
        }

        notEmpty(inputData[1], "Action");
        action = IntegrationTestAction.getByName(inputData[1]);

        errorCode = getErrorCodeByName(inputData[2]);
        errorMessage = inputData[3].isEmpty() ? null : inputData[3];
        inputHash = inputData[4].isEmpty() ? null : new DataHash(Base16.decode(inputData[4]));
        chcInputHash = inputData[5].isEmpty() ? null : new DataHash(Base16.decode(inputData[5]));
        chchOutputHash = inputData[6].isEmpty() ? null : new DataHash(Base16.decode(inputData[6]));
        registrationTime = inputData[7].isEmpty() ? null : new Date(Long.decode(inputData[7]) * 1000L);
        aggregationTime = inputData[8].isEmpty() ? null : new Date(Long.decode(inputData[8]) * 1000L);
        publicationTime = inputData[9].isEmpty() ? null : new Date(Long.decode(inputData[9]) * 1000L);
        userPublication = inputData[10].isEmpty() ? null : new PublicationData(inputData[10]);
        extendingPermitted = inputData[11].isEmpty() ? false : Boolean.valueOf(inputData[11]);

        this.settings = loadHTTPSettings();
        buildKsi();
    }

    private void buildKsi() throws IOException, KSIException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        SimpleHttpClient httpClient = new SimpleHttpClient(settings);
        KSIBuilder builder = new KSIBuilder();
        builder.setKsiProtocolPublicationsFileClient(httpClient).
                setKsiProtocolSignerClient(httpClient).
                setPublicationsFilePkiTrustStore(createKeyStore()).
                setPublicationsFileTrustedCertSelector(createCertSelector()).
                setDefaultVerificationPolicy(new AlwaysSuccessfulPolicy()).
                setPduIdentifierProvider(new DefaultPduIdentifierProvider()).
                setDefaultSigningHashAlgorithm(HashAlgorithm.SHA2_256);

        if (responseFile != null) {

            builder.setKsiProtocolExtenderClient(mockExtenderClient());
        } else {
            builder.setKsiProtocolExtenderClient(extenderClient);
        }

        this.ksi = builder.build();
    }

    public VerificationContext getVerificationContext(KSISignature signature) throws KSIException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {

        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).
                setExtenderClient(responseFile == null ? extenderClient : mockExtenderClient()).
                setPublicationsFile(publicationsFile == null ? ksi.getPublicationsFile() : getPublicationsFile()).
                setUserPublication(userPublication).
                setExtendingAllowed(extendingPermitted).
                setDocumentHash(inputHash);
        VerificationContext context = builder.createVerificationContext();
        context.setPduFactory(new PduV2Factory());
        context.setKsiSignatureComponentFactory(new InMemoryKsiSignatureComponentFactory());
        return context;
    }

    private SimpleHttpClient mockExtenderClient() throws KSIException, IOException {
        final TLVElement responseTLV = TLVElement.create(IOUtils.toByteArray(load(responseFile)));
        SimpleHttpClient mockClient = Mockito.mock(SimpleHttpClient.class);
        final SimpleHttpPostRequestFuture mockedFuture = Mockito.mock(SimpleHttpPostRequestFuture.class);
        Mockito.when(mockedFuture.isFinished()).thenReturn(Boolean.TRUE);
        Mockito.when(mockedFuture.getResult()).thenReturn(responseTLV);
        Mockito.when(mockClient.getServiceCredentials()).thenReturn(settings.getCredentials());
        Mockito.when(mockClient.getPduVersion()).thenReturn(PduVersion.V2);

        Mockito.when(mockClient.extend(Mockito.any(InputStream.class))).then(new Answer<Future>() {
            public Future answer(InvocationOnMock invocationOnMock) throws Throwable {
                InputStream input = (InputStream) invocationOnMock.getArguments()[0];
                TLVElement tlvElement = TLVElement.create(Util.toByteArray(input));
                ByteOutputStream bos = new ByteOutputStream();
                responseTLV.getFirstChildElement(0x2).getFirstChildElement(0x01).setLongContent(tlvElement.getFirstChildElement(0x2).getFirstChildElement(0x1).getDecodedLong());

                responseTLV.getFirstChildElement(0x1F).setDataHashContent(calculateHash(responseTLV, responseTLV.getFirstChildElement(0x1F).getDecodedDataHash().getAlgorithm(), settings.getCredentials().getLoginKey()));
                return mockedFuture;
            }
        });
        return mockClient;
    }

    private DataHash calculateHash(TLVElement rootElement, HashAlgorithm macAlgorithm, byte[] loginKey) throws Exception {
        byte[] tlvBytes = rootElement.getEncoded();
        byte[] macCalculationInput = Util.copyOf(tlvBytes, 0, tlvBytes.length - macAlgorithm.getLength());
        return new DataHash(macAlgorithm, Util.calculateHMAC(macCalculationInput, loginKey, macAlgorithm.getName()));
    }

    private PublicationsFile getPublicationsFile() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, KSIException {
        InMemoryPublicationsFileFactory factory = new InMemoryPublicationsFileFactory(new JKSTrustStore(createKeyStore(), createCertSelector()));
        return factory.create(load(publicationsFile));
    }

    private void notEmpty(String object, String name) {
        if (object.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " is empty.");
        }
    }

    private void notNull(Object object, String name) {
        if (object == null) {
            throw new IllegalArgumentException(name + " is null.");
        }
    }

    private VerificationErrorCode getErrorCodeByName(String name) {
        for (VerificationErrorCode code : VerificationErrorCode.values()) {
            if (code.getCode().equals(name)) {
                return code;
            }
        }
        return null;
    }

    public String toString() {
        return "TestData{" +
                " testFile=" + testFile +
                ", action=" + action.getName() +
                ", errorCode=" + (errorCode == null ? "" : errorCode.getCode()) +
                ", errorMessage=" + errorMessage +
                ", inputHash=" + inputHash +
                ", chcInputHash=" + chcInputHash +
                ", chchOutputHash=" + chchOutputHash +
                ", registrationTime=" + (registrationTime == null ? "" : registrationTime.getTime()) +
                ", aggregationTime=" + (aggregationTime == null ? "" : aggregationTime.getTime()) +
                ", publicationTime=" + (publicationTime == null ? "" : publicationTime.getTime()) +
                ", userPublication=" + (userPublication == null ? "" : userPublication.getPublicationString()) +
                ", extendingPermitted=" + extendingPermitted +
                ", responseFile=" + responseFile +
                ", publicationsFile=" + publicationsFile +
                " }";
    }

    public String getTestFile() {
        return testFile;
    }

    public IntegrationTestAction getAction() {
        return action;
    }

    public VerificationErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public DataHash getInputHash() {
        return inputHash;
    }

    public DataHash getChcInputHash() {
        return chcInputHash;
    }

    public DataHash getChchOutputHash() {
        return chchOutputHash;
    }

    public Date getRegistrationTime() {
        return registrationTime;
    }

    public Date getAggregationTime() {
        return aggregationTime;
    }

    public Date getPublicationTime() {
        return publicationTime;
    }

    public PublicationData getUserPublication() {
        return userPublication;
    }

    public boolean isExtendingPermitted() {
        return extendingPermitted;
    }

    public String getResponseFile() {
        return responseFile;
    }

    public KSI getKsi() {
        return ksi;
    }
}
