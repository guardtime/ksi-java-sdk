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

package com.guardtime.ksi.unisignature;

/**
 * This interface represents PKI signature data. Signature data contains the following elements: <ul> <li> `signature
 * type': a signing algorithm and signature format identifier, as assigned by IANA, represented as an UTF-8 string
 * containing a dotted decimal object identifier (OID); </li> <li> `signature value': the signature itself, computed and
 * formatted according to the specified method; </li> <li> `certificate identifier' and optionally `certificate
 * repository URI', with the latter pointing to a repository that contains the certificate identified by the
 * `certificate identifier'. </li> </ul>
 */
public interface SignatureData {

    /**
     * Signature data element type.
     */
    int ELEMENT_TYPE = 0x0b;

    String getSignatureType();

    /**
     * @return returns signature value. always present.
     */
    byte[] getSignatureValue();

    /**
     * @return returns certificate id. always presents.
     */
    byte[] getCertificateId();

    /**
     * @return returns certificate repository uri. returns null is repository uri isn't present.
     */
    String getCertificateRepositoryUri();
}
