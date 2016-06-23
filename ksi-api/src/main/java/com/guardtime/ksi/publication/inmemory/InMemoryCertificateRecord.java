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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

/**
 * Certificate record element. Holds certificate id and certificate used by publication file.
 */
class InMemoryCertificateRecord extends TLVStructure {

    public static final int ELEMENT_TYPE = 0x702;
    private static final int ELEMENT_TYPE_CERTIFICATE_ID = 0x01;
    private static final int ELEMENT_TYPE_CERTIFICATE = 0x02;

    private byte[] certificateId;
    private byte[] certificate;

    /**
     * Constructor to createSignature "Certificate Record" element form {@link TLVElement}.
     *
     * @param rootElement
     *         element to be used to
     */
    public InMemoryCertificateRecord(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_CERTIFICATE_ID:
                    this.certificateId = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_CERTIFICATE:
                    this.certificate = readOnce(child).getContent();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (certificateId == null) {
            throw new InvalidPublicationsFileException("Certificate Id can not be null");
        }
        if (certificate == null) {
            throw new InvalidPublicationsFileException("Certificate can not be null");
        }
    }

    /**
     * @return returns the certificate byte array
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * @return certificate id byte array
     */
    public byte[] getCertificateId() {
        return certificateId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }
}
