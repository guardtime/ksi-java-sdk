package com.guardtime.ksi.unisignature;

import org.testng.annotations.Test;

public class IdentityMetadataTest {

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Client Identifier can not be null")
    public void testCreateNewWithoutClientId_ThrowsNullPointerException() throws Exception {
        new IdentityMetadata(null);
    }

}