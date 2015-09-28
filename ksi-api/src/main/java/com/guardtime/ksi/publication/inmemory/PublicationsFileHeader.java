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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.Date;
import java.util.List;

/**
 * Publications file header. Contains the following data: <ul> <li>the version number of the file format</li> <li>time
 * when the file was created</li> <li>URI of the the canonical distribution point of the file</li> </ul>
 */
class PublicationsFileHeader extends TLVStructure {

    static final int ELEMENT_TYPE = 0x0701;
    private static final int ELEMENT_TYPE_VERSION = 0x01;
    private static final int ELEMENT_TYPE_CREATION_TIME = 0x02;
    private static final int ELEMENT_TYPE_REPOSITORY_URI = 0x03;

    private Long version;
    private Date creationTime;
    private String repositoryUri;

    PublicationsFileHeader(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_VERSION:
                    version = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_CREATION_TIME:
                    creationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_REPOSITORY_URI:
                    repositoryUri = readOnce(child).getDecodedString();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (version == null) {
            throw new InvalidPublicationsFileException("Publications file header version element must be present");
        }
        if (creationTime == null) {
            throw new InvalidPublicationsFileException("Publications file header creation time element must be present");
        }
    }

    public Long getVersion() {
        return version;
    }

    public Date getCreationTime() {
        return creationTime;
    }

    public String getRepositoryUri() {
        return repositoryUri;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
