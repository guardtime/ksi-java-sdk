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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.tlv.TLVInputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;

public class PublicationsFileHeaderTest {

    @Test
    public void testDecodePublicationFileHeader_Ok() throws Exception {
        PublicationsFileHeader header = load("publications-file/publications-file-header-ok.tlv");
        Assert.assertEquals(header.getVersion().longValue(), 2L);
        Assert.assertEquals(header.getCreationTime(), new Date(123456000L));
        Assert.assertEquals(header.getRepositoryUri(), "repository");
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Publications file header version element must be present")
    public void testDecodePublicationsFileHeaderWithoutVersion_ThrowsInvalidPublicationsFileException() throws Exception {
        load("publications-file/publications-file-header-version-missing.tlv");
    }

    @Test(expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Publications file header creation time element must be present")
    public void testDecodePublicationFileHeaderWithoutCreationTime_ThrowsInvalidPublicationsFileException() throws Exception {
        load("publications-file/publications-file-header-creation-time-missing.tlv");
    }

    private PublicationsFileHeader load(String file) throws Exception {
        TLVInputStream input = new TLVInputStream(TestUtil.load(file));
        try {
            return new PublicationsFileHeader(input.readElement());
        } finally {
            input.close();
        }
    }

}