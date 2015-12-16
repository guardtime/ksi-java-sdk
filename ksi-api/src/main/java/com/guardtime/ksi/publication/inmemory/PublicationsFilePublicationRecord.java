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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * A KSI publication record represents the information related to a published hash value, possibly including the
 * publication reference. Publication may also point (via a URI) to a hash database that is in electronic form and may
 * contain several published hash values. A publication record structure contains the following fields:<ul>
 * <li>`published data': consists of a `publication time' and a `published hash'; </li> <li>`publication reference': an
 * UTF-8 string that contains the bibliographic reference to a media outlet where the publication appeared;</li>
 * <li>`publications repository URI': URI of a publications repository (publication file).</li> </ul> <p> This class is
 * a abstract class for publications file record and signature publication record. Contains common logic for both
 * publication records. </p>
 */
public class PublicationsFilePublicationRecord extends TLVStructure implements PublicationRecord {

    public static final int ELEMENT_TYPE = 0x703;
    private static final int ELEMENT_TAG_PUBLICATION_REFERENCE = 0x09;
    private static final int ELEMENT_TAG_PUBLICATION_REPOSITORY_URI = 0x0A;

    private PublicationData publicationData;
    private final List<String> publicationReferences = new LinkedList<String>();
    private final List<String> publicationRepositoryURIs = new LinkedList<String>();

    /**
     * Reads publication record from TLV element.
     *
     * @param rootElement
     *         TLV element to createSignature
     */
    public PublicationsFilePublicationRecord(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case PublicationData.ELEMENT_TYPE:
                    this.publicationData = new PublicationData(readOnce(child));
                    continue;
                case ELEMENT_TAG_PUBLICATION_REFERENCE:
                    publicationReferences.add(child.getDecodedString());
                    continue;
                case ELEMENT_TAG_PUBLICATION_REPOSITORY_URI:
                    publicationRepositoryURIs.add(child.getDecodedString());
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }

        if (publicationData == null) {
            throw new InvalidPublicationRecordException("publicationData", PublicationData.ELEMENT_TYPE, "PublicationRecord", getElementType());
        }
    }

    public PublicationsFilePublicationRecord(PublicationData publicationData) throws TLVParserException {
        this.publicationData = publicationData;
        this.rootElement = new TLVElement(false, false, getElementType());
        this.rootElement.addChildElement(publicationData.getRootElement());
    }

    public Date getPublicationTime() {
        return publicationData.getPublicationTime();
    }

    /**
     * @return returns instance of {@link PublicationData}. always present.
     */
    public PublicationData getPublicationData() {
        return publicationData;
    }

    /**
     * @return returns list of publication references or empty list.
     */
    public List<String> getPublicationReferences() {
        return publicationReferences;
    }

    /**
     * @return return list of publication repository URI's or empty list.
     */
    public List<String> getPublicationRepositoryURIs() {
        return publicationRepositoryURIs;
    }

    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
