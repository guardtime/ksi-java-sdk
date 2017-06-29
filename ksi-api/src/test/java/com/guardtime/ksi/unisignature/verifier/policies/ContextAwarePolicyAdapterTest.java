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

import com.guardtime.ksi.Extender;
import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.KSIExtendingService;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

public class ContextAwarePolicyAdapterTest {

    @Test
    public void testInternalVerificationPolicyCreation() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createInternalPolicy();
        assertNotNull(policy);
        assertEquals(policy.getName(), "Internal verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNull(policy.getPolicyContext().getExtendingService());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertFalse(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test
    public void testKeyBasedVerificationPolicyCreation() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createKeyPolicy(Mockito.mock(PublicationsHandler.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "Key-based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNull(policy.getPolicyContext().getExtendingService());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertFalse(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Publications handler can not be null")
    public void testKeyBasedVerificationPolicyCreationNoPublicationsHandler() {
        ContextAwarePolicyAdapter.createKeyPolicy(null);
    }

    @Test
    public void testPublicationsFileBasedVerificationPolicyCreation() {
        ContextAwarePolicy policy =
                ContextAwarePolicyAdapter.createPublicationsFilePolicy(Mockito.mock(PublicationsHandler.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "Publications file based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNull(policy.getPolicyContext().getExtendingService());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertFalse(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Publications handler can not be null")
    public void testPublicationsFileBasedVerificationPolicyCreationNoPublicationsHandler() {
        ContextAwarePolicyAdapter.createPublicationsFilePolicy(null);
    }

    @Test
    public void testCalendarBasedVerificationPolicyCreation() {
        Extender extender = Mockito.mock(Extender.class);
        Mockito.when(extender.getExtendingService()).thenReturn(Mockito.mock(KSIExtendingService.class));
        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createCalendarPolicy(extender);
        assertNotNull(policy);
        assertEquals(policy.getName(), "Calendar-based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtendingService());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Extender can not be null")
    public void testCalendarBasedVerificationPolicyCreationNoExtender() {
        ContextAwarePolicyAdapter.createCalendarPolicy(null);
    }

    @Test
    public void testUserProvidedPublicationBasedVerificationPolicyCreation() {
        Extender extender = Mockito.mock(Extender.class);
        Mockito.when(extender.getExtendingService()).thenReturn(Mockito.mock(KSIExtendingService.class));
        ContextAwarePolicy policy = ContextAwarePolicyAdapter
                .createUserProvidedPublicationPolicy(Mockito.mock(PublicationData.class), extender);
        assertNotNull(policy);
        assertEquals(policy.getName(), "User provided publication based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtendingService());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Publication data can not be null")
    public void testUserProvidedPublicationBasedVerificationPolicyCreationNoPublicationData() {
        ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(null, Mockito.mock(Extender.class));
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Extender can not be null")
    public void testUserProvidedPublicationBasedVerificationPolicyCreationNoExtender() {
        ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(Mockito.mock(PublicationData.class), null);
    }

    @Test
    public void testPolicyCreation() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createPolicy(new KeyBasedVerificationPolicy(),
                Mockito.mock(PublicationsHandler.class), Mockito.mock(KSIExtendingService.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "Key-based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtendingService());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Publications handler can not be null")
    public void testPolicyCreationNoPublicationsHandler() {
        ContextAwarePolicyAdapter.createPolicy(new KeyBasedVerificationPolicy(), null, Mockito.mock(KSIExtendingService.class));
    }

    @Test(expectedExceptions = NullPointerException.class,
            expectedExceptionsMessageRegExp = "Extending service can not be null")
    public void testPolicyCreationNoExtender() {
        ContextAwarePolicyAdapter.createPolicy(new KeyBasedVerificationPolicy(), Mockito.mock(PublicationsHandler.class), null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Unsupported verification policy.")
    public void testPolicyCreationUnsupportedPolicy() {
        ContextAwarePolicyAdapter.createPolicy(new UserProvidedPublicationBasedVerificationPolicy(),
                Mockito.mock(PublicationsHandler.class), Mockito.mock(KSIExtendingService.class));
    }
}
