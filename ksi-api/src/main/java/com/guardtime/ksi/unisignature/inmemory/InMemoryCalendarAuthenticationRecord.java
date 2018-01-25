/*
 * Copyright 2013-2018 Guardtime, Inc.
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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.SignatureData;

import java.util.List;

/**
 * <p> A calendar authentication record is used to sign the output hash value of a calendar hash chain and corresponds
 * to a calendar hash chain.</p>
 * <p/>
 * A calendar authentication record contains the following fields: <ul> <li>`published data': consists of a `publication
 * time' and a `published hash', which contain the `publication time' and the output hash value, respectively, of the
 * calendar hash chain the authentication record belongs to. </li> <li> `signature data' that contains the following
 * fields: <ul> <li>`signature type': a signing algorithm and signature format identifier, as assigned by IANA,
 * represented as an UTF-8 string containing a dotted decimal object identifier (OID);</li>
 * <p/>
 * <li>`signature value': the signature itself, computed and formatted according to the specified method;</li>
 * <p/>
 * <li>`certificate identifier' and optionally `certificate repository URI', with the latter pointing to a repository
 * (e.g. a publication file) that contains the certificate identified by the `certificate identifier'.</li> </ul>
 * <p/>
 * </li> </ul>
 */
class InMemoryCalendarAuthenticationRecord extends TLVStructure implements CalendarAuthenticationRecord {

    public static final int ELEMENT_TYPE = 0x0805;

    private PublicationData publicationData;
    private InMemorySignatureData signatureData;

    /**
     * Constructor for decoding calendar authentication record.
     *
     * @param rootElement
     *         TLV element used createSignature calendar authentication record.
     */
    public InMemoryCalendarAuthenticationRecord(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case PublicationData.ELEMENT_TYPE:
                    this.publicationData = new PublicationData(readOnce(child));
                    continue;
                case SignatureData.ELEMENT_TYPE:
                    this.signatureData = new InMemorySignatureData(readOnce(child));
                    continue;
                default:
                    verifyCriticalFlag(child);
            }

        }
        if (publicationData == null) {
            throw new InvalidCalendarAuthenticationRecordException("Calendar authentication does not contain publication data");
        }
        if (signatureData == null) {
            throw new InvalidCalendarAuthenticationRecordException("Calendar authentication record does not contain signature data");
        }
    }


    public PublicationData getPublicationData() {
        return publicationData;
    }

    /**
     * @return returns signature data. always present.
     */
    public SignatureData getSignatureData() {
        return signatureData;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
