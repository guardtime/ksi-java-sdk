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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;

/**
 * An older implementation of the KSI service used the formats and protocols specified in the X.509 time-stamping
 * standard (RFC 3161). In that format, the hash value of the time-stamped datum was not signed directly, but via
 * several intermediate structures.
 * <p/>
 * To facilitate conversion of legacy KSI signatures issued in the RFC 3161 format, the helper data structure is used,
 * whit the following fields <ul> <li>The `aggregation time', `chain index' and `input hash' fields have the same
 * meaning as in the `aggregation chain' structure defined in Section 4.1.1.</li><li> The `tstinfo prefix' and `tstinfo
 * suffix' fields contain the data preceding and succeeding the hash value within the TSTInfo structure.</li><li> The
 * `tstinfo algorithm' field contains the one-byte identifier (as defined in Table 2) of the hash function used to hash
 * the TSTInfo structure.</li><li> The `signed attributes prefix' and `signed attributes suffix' fields contain the data
 * preceding and succeeding the hash value within the SignedAttributes structure.</li><li> The `signed attributes
 * algorithm' field contains the one-byte identifier of the hash function used to hash the SignedAttributes
 * structure.</li> </ul>
 */
public interface RFC3161Record {

    int ELEMENT_TYPE = 0x806;

    /**
     * Returns the RFC3161 record input data hash
     */
    DataHash getInputHash();

    /**
     * Returns the RFC3161 record output data hash
     */
    DataHash getOutputHash(HashAlgorithm hashAlgorithm) throws HashException;
}
