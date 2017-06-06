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
        assertNull(policy.getPolicyContext().getExtender());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
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
        assertNull(policy.getPolicyContext().getExtender());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertFalse(policy.getPolicyContext().isExtendingAllowed());
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
        assertNull(policy.getPolicyContext().getExtender());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertFalse(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test
    public void testPublicationsFileBasedVerificationPolicyCreationWithExtender() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter
                .createPublicationsFilePolicy(Mockito.mock(PublicationsHandler.class), Mockito.mock(Extender.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "Publications file based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtender());
        assertNotNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test
    public void testCalendarBasedVerificationPolicyCreation() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter
                .createCalendarPolicy(Mockito.mock(Extender.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "Calendar-based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtender());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
        assertNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }

    @Test
    public void testUserProvidedPublicationBasedVerificationPolicyCreation() {
        ContextAwarePolicy policy = ContextAwarePolicyAdapter
                .createUserPolicy(Mockito.mock(PublicationData.class), Mockito.mock(Extender.class));
        assertNotNull(policy);
        assertEquals(policy.getName(), "User provided publication based verification policy");
        assertNotNull(policy.getType());
        assertNotNull(policy.getRules());
        assertNotNull(policy.getPolicyContext());
        assertNotNull(policy.getPolicyContext().getExtender());
        assertNull(policy.getPolicyContext().getPublicationsHandler());
        assertNotNull(policy.getPolicyContext().getSignatureComponentFactory());
        assertNotNull(policy.getPolicyContext().getUserPublication());
        assertTrue(policy.getPolicyContext().isExtendingAllowed());
    }
}
