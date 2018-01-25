/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.publication;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Base32;
import com.guardtime.ksi.util.Util;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Record of publication data, it is a pair consisting of the publication time and publication hash. It's TLV encoded
 * form is used for signing and verifying authentication records.
 */
public class PublicationData extends TLVStructure {

    public static final int ELEMENT_TYPE = 0x10;

    private static final int ELEMENT_TYPE_PUBLICATION_TIME = 2;
    private static final int ELEMENT_TYPE_PUBLICATION_HASH = 4;

    private Date publicationTime;
    private DataHash publicationHash;

    /**
     * Creates a new publication data from TLV element. Parses publication time and publication hash elements from
     * {@link TLVElement}. TLV element must contain publication hash and publication time elements.
     *
     * @param rootElement
     *         - TLV element to parse to publication data. not null.
     */
    public PublicationData(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_PUBLICATION_HASH:
                    this.publicationHash = readOnce(child).getDecodedDataHash();
                    continue;
                case ELEMENT_TYPE_PUBLICATION_TIME:
                    this.publicationTime = readOnce(child).getDecodedDate();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        verifyRequiredElements();
    }

    /**
     * Create a publication object from a publication string. A publication string is a base-32 encoded value that is
     * meant published to print media as human readable text or a QR code.
     *
     * @param publicationString
     *         publication in string format. not null.
     */
    public PublicationData(String publicationString) throws KSIException {
        if (publicationString == null) {
            throw new InvalidPublicationDataException("Publication data publication string can not be null");
        }
        byte[] publicationStringBytes = Base32.decode(publicationString);
        // Length needs to be at least 13 bytes (8 bytes for time plus non-empty hash imprint plus 4 bytes for crc32)
        if (publicationStringBytes == null || publicationStringBytes.length < 13) {
            throw new InvalidPublicationDataException("Invalid publication string: Base32 decode failed");
        }
        byte[] crc = Util.calculateCrc32(publicationStringBytes, 0, publicationStringBytes.length - 4);
        if (!Arrays.equals(crc, Util.copyOf(publicationStringBytes, publicationStringBytes.length - 4, 4))) {
            throw new InvalidPublicationDataException("Invalid publication string: CRC32 Check failed");
        }

        byte[] hashImprint = Util.copyOf(publicationStringBytes, 8, publicationStringBytes.length - 12);
        this.publicationTime = new Date(Util.toLong(publicationStringBytes) * 1000);
        this.publicationHash = new DataHash(hashImprint);
        verifyRequiredElements();
        createRootTLVElement();
    }

    /**
     * Creates a new instance of publication data using publication time and publication hash.
     *
     * @param publicationTime
     *         - publication time. not null.
     * @param publicationHash
     *         - publication hash. not null.
     */
    public PublicationData(Date publicationTime, DataHash publicationHash) throws KSIException {
        this.publicationTime = publicationTime;
        this.publicationHash = publicationHash;
        verifyRequiredElements();
        createRootTLVElement();
    }

    private void verifyRequiredElements() throws InvalidPublicationDataException {
        if (this.publicationTime == null) {
            throw new InvalidPublicationDataException("Publication data publication time can not be null");
        }
        if (this.publicationHash == null) {
            throw new InvalidPublicationDataException("Publication data publication hash can not be null");
        }
    }

    private void createRootTLVElement() throws TLVParserException {
        this.rootElement = new TLVElement(false, true, ELEMENT_TYPE);

        //publication time
        TLVElement publicationTimeElement = new TLVElement(false, false, ELEMENT_TYPE_PUBLICATION_TIME);
        publicationTimeElement.setLongContent(publicationTime.getTime() / 1000);
        rootElement.addChildElement(publicationTimeElement);

        //published hash
        TLVElement publicationHashElement = new TLVElement(false, false, ELEMENT_TYPE_PUBLICATION_HASH);
        publicationHashElement.setDataHashContent(publicationHash);
        rootElement.addChildElement(publicationHashElement);
    }

    /**
     * @return - returns publication data publication time. always present.
     */
    public Date getPublicationTime() {
        return publicationTime;
    }

    /**
     * @return returns the published hash. always present.
     */
    public DataHash getPublicationDataHash() {
        return publicationHash;
    }

    /**
     * Returns a publication string that is a base-32 encoded value that is meant published to print media as human
     * readable text
     *
     * @return returns a base-32 encoded publication string
     */
    public String getPublicationString() {
        byte[] imprint = publicationHash.getImprint();
        byte[] data = new byte[imprint.length + 8];
        System.arraycopy(Util.toByteArray(publicationTime.getTime() / 1000), 0, data, 0, 8);
        System.arraycopy(imprint, 0, data, 8, imprint.length);

        return Base32.encodeWithDashes(Util.addCrc32(data));
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    /**
     * @return returns publication data TLV encoded byte array
     */
    public byte[] getEncoded() throws TLVParserException {
        return rootElement.getEncoded();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PublicationData that = (PublicationData) o;

        if (!publicationTime.equals(that.publicationTime)) return false;
        return publicationHash.equals(that.publicationHash);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + publicationTime.hashCode();
        result = 31 * result + publicationHash.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "T=" + publicationTime.getTime() / 1000 + ", " + publicationHash;
    }
}
