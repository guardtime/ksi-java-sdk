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
package com.guardtime.ksi.service;

import java.util.Date;

import com.guardtime.ksi.exceptions.KSIException;
import org.testng.annotations.Test;

import com.guardtime.ksi.service.extension.ExtensionRequestPayload;
import com.guardtime.ksi.util.Util;

public class ExtensionRequestPayloadTest {

    @Test(expectedExceptions = KSIProtocolException.class)
    public void testCreateExtensionRequestTimeFail() throws KSIException {
        new ExtensionRequestPayload(new Date(423654196), new Date(421280000), Util.nextLong());
    }
}
