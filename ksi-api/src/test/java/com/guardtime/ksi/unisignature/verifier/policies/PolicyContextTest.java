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
package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertFalse;

public class PolicyContextTest {

    @Test
    public void testPolicyContextWithoutParams() {
        PolicyContext pc = new PolicyContext();
        assertFalse(pc.isExtendingAllowed());
        assertNull(pc.getExtenderClient());
        assertNull(pc.getPublicationsHandler());
        assertNull(pc.getUserPublication());
    }

    @Test
    public void testPolicyContextWithExtender() {
        PolicyContext pc = new PolicyContext(Mockito.mock(KSIExtenderClient.class));
        assertTrue(pc.isExtendingAllowed());
        assertNotNull(pc.getExtenderClient());
        assertNull(pc.getPublicationsHandler());
        assertNull(pc.getUserPublication());
    }

    @Test
    public void testPolicyContextWithPublicationsHandlerExtender() {
        PolicyContext pc = new PolicyContext(Mockito.mock(PublicationsHandler.class), Mockito.mock(KSIExtenderClient.class));
        assertTrue(pc.isExtendingAllowed());
        assertNotNull(pc.getExtenderClient());
        assertNotNull(pc.getPublicationsHandler());
        assertNull(pc.getUserPublication());
    }

    @Test
    public void testPolicyContextWithPublicationDataExtender() {
        PolicyContext pc = new PolicyContext(Mockito.mock(PublicationData.class), Mockito.mock(KSIExtenderClient.class));
        assertTrue(pc.isExtendingAllowed());
        assertNotNull(pc.getExtenderClient());
        assertNull(pc.getPublicationsHandler());
        assertNotNull(pc.getUserPublication());
    }

}
