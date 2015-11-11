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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.SignatureData;

import java.util.List;

/**
 * This class represents PKI signature data. Signature data contains the following elements: <ul> <li> `signature type':
 * a signing algorithm and signature format identifier, as assigned by IANA, represented as an UTF-8 string containing a
 * dotted decimal object identifier (OID); </li> <li> `signature value': the signature itself, computed and formatted
 * according to the specified method; </li> <li> `certificate identifier' and optionally `certificate repository URI',
 * with the latter pointing to a repository that contains the certificate identified by the `certificate identifier'.
 * </li> </ul>
 */
class InMemorySignatureData extends TLVStructure implements SignatureData {

    private static final int ELEMENT_TYPE_SIGNATURE_TYPE = 0x01;
    private static final int ELEMENT_TYPE_SIGNATURE_VALUE = 0x02;
    private static final int ELEMENT_TYPE_CERTIFICATE_ID = 0x03;
    private static final int ELEMENT_TYPE_CERTIFICATE_REPOSITORY_URI = 0x04;

    private String signatureType;

    private byte[] signatureValue;

    private byte[] certificateId;

    private String certificateRepositoryUri;

    /**
     * Constructor for creating new signature data elements from {@link TLVElement}.
     *
     * @param rootElement
     *         TLV element to be used to createSignature signature data element
     */
    public InMemorySignatureData(TLVElement rootElement) throws KSIException {
        super(rootElement);
        List<TLVElement> children = rootElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_SIGNATURE_TYPE:
                    this.signatureType = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_SIGNATURE_VALUE:
                    this.signatureValue = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_CERTIFICATE_ID:
                    this.certificateId = readOnce(child).getContent();
                    continue;
                case ELEMENT_TYPE_CERTIFICATE_REPOSITORY_URI:
                    this.certificateRepositoryUri = readOnce(child).getDecodedString();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (signatureType == null) {
            throw new InvalidSignatureDataException("Signature data signature type can not be null");
        }
        if (signatureValue == null) {
            throw new InvalidSignatureDataException("Signature data signature value can not be null");
        }
        if (certificateId == null) {
            throw new InvalidSignatureDataException("Signature data certificate id can not be null");
        }
    }

    /**
     * @return returns signature type. always present.
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * @return returns signature value. always present.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }

    /**
     * @return returns certificate id. always presents.
     */
    public byte[] getCertificateId() {
        return certificateId;
    }

    /**
     * @return returns certificate repository uri. returns null is repository uri isn't present.
     */
    public String getCertificateRepositoryUri() {
        return certificateRepositoryUri;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
