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

package com.guardtime.ksi.multisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.multisignature.file.FileBasedMultiSignatureFactory;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.KSISignature;

/**
 * <p> KSI multi signature is a container format for storing multiple keyless uni-signatures. This interface is designed
 * to: <ul> <li>add uni signatures to the container</li> <li>searching for a uni-signature in the container using the
 * document hash</li> <li>deleting a uni-signature from a container using the document hash </li> <li>list all used hash
 * algorithms used by the uni-signatures</li> <li>extending signature</li></ku></ul> <p/> <p>NB! To createSignature a instance of
 * {@link KSIMultiSignature} use one of the {@link KSIMultiSignatureFactory} implementation.</p>
 *
 * @see KSIMultiSignatureFactory
 * @see FileBasedMultiSignatureFactory
 */
public interface KSIMultiSignature {

    /**
     * This method is used to add uni-signature to the container.
     *
     * @param signature
     *         uni-signature ti be added to the container
     * @throws KSIException
     *         will be thrown when adding signature to the container fails.
     */
    void add(KSISignature signature) throws KSIException;

    /**
     * This method is used to search a uni-signature from the container.
     *
     * @param documentHash
     *         document hash that is used to search signatures.
     * @return instance of uni-signature. always present.
     * @throws KSIException
     *         will be thrown when signature isn't present or error occurs turning the search.
     */
    KSISignature get(DataHash documentHash) throws KSIException;

    /**
     * This method is used to remove uni-signature from the container.
     *
     * @param documentHash
     *         document hash to be used to remove signature
     * @throws KSIException
     *         will be thrown when error occurs
     */
    void remove(DataHash documentHash) throws KSIException;

    /**
     * This method returns the list of hash algorithms used by uni-signatures inside this multi signature container.
     *
     * @return list of hash algorithms. when multi signature container does not contain any uni-signatures then empty
     * list is returned.
     */
    HashAlgorithm[] getUsedHashAlgorithms();


    /**
     * <p>When called, all unextended signatures are extended to the closest (oldest) publication possible. If there is
     * no suitable publication to extend one signature - that signature will not be extended.</p> <p>If there are more
     * than one signature per round then only one extending request is sent</p>
     *
     * @param trustStore
     *         KSI trust store to be used to search suitable publications.
     */
    void extend(PublicationsFile trustStore) throws KSIException;

    /**
     * <p> When called all (inc already extended) signatures are extended to a specific publication. Signature isn't
     * extended if a signature is a newer than the given publication. <p/>
     *
     * @param publicationRecord
     *         publication to extend
     */
    void extend(PublicationRecord publicationRecord) throws KSIException;

}
