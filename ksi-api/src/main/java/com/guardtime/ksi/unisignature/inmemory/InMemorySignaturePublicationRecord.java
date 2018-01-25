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
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;

import java.util.List;

/**
 * @see com.guardtime.ksi.unisignature.SignaturePublicationRecord
 * @see com.guardtime.ksi.publication.PublicationRecord
 */
public class InMemorySignaturePublicationRecord extends PublicationsFilePublicationRecord implements SignaturePublicationRecord {


    public InMemorySignaturePublicationRecord(TLVElement rootElement) throws KSIException {
        super(rootElement);
    }

    public InMemorySignaturePublicationRecord(PublicationData publicationData, List<String> references, List<String> uris) throws TLVParserException {
        super(publicationData, references, uris);
    }

    public int getElementType() {
        return SignaturePublicationRecord.ELEMENT_TYPE;
    }

}
