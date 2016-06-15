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

import com.guardtime.ksi.service.client.KSIExtenderClient;

public class DataHolderForIntegrationTests {

    private String testFile;
    private boolean expectException;
    private boolean expectFailureWithErrorCode;
    private String expectedFailureCode;
    private String expectedExceptionClass;
    private String exceptionMessage;
    private KSIExtenderClient httpClient;

    public DataHolderForIntegrationTests(String[] inputData, KSIExtenderClient httpClient) throws Exception {
        if (inputData[0] == null) {
            throw new IllegalArgumentException("Test file is null");
        }
        this.testFile = inputData[0];
        this.expectException = Boolean.valueOf(inputData[1].trim());
        this.expectFailureWithErrorCode =  Boolean.valueOf(inputData[2].trim());

        if (inputData[3] == null) {
            throw new IllegalArgumentException("Failure code is null");
        }
        this.expectedFailureCode = inputData[3];

        if (inputData[4] == null) {
            throw new IllegalArgumentException("Expected exception is null");
        }
        this.expectedExceptionClass = inputData[4];

        if (inputData[5] == null) {
            throw new IllegalArgumentException("Expected exception message is null");
        }
        this.exceptionMessage = inputData[5];

        if (httpClient == null) {
            throw new IllegalArgumentException("HttpClientSettings is null");
        }
        this.httpClient = httpClient;

    }

    public String getTestFile() {
        return testFile;
    }

    public boolean getExpectException() {
        return expectException;
    }

    public boolean getExpectFailureWithErrorCode() {
        return expectFailureWithErrorCode;
    }

    public String getExpectedFailureCode() {
        return expectedFailureCode;
    }

    public String getExpectedExceptionClass() {
        return expectedExceptionClass;
    }

    public String getExpectedExceptionMessage() {
        return exceptionMessage;
    }

    public KSIExtenderClient getHttpClient() {
        return httpClient;
    }

    public void setTestFile(String testFile) {
        this.testFile = testFile;
    }

    public void setHttpClient(KSIExtenderClient httpClient) {
        this.httpClient = httpClient;
    }

    public String getTestDataInformation() {
        return "Signature File: " + testFile + "; Pass Internal Verification: " + expectException +
                "; Pass Verification: " + expectFailureWithErrorCode + "; Failure Code: " + expectedFailureCode +
                "; Expected Exception Class: " + expectedExceptionClass + "; Expected Exception Message: " + exceptionMessage;
    }
}
