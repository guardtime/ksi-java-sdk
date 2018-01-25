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

import java.util.Date;
import java.util.List;

/**
 * A `publication record' represents the information related to a published hash value, possibly including the
 * publication reference. Publication may also point (via a URI) to a hash database that is in electronic form and may
 * contain several published hash values
 */
public interface PublicationRecord {

    /**
     * @return returns the publication data of this publication record
     */
    PublicationData getPublicationData();

    /**
     * Same as  {@link PublicationData#getPublicationTime()}
     */
    Date getPublicationTime();

    /**
     * @return returns list of publication references or empty list.
     */
    List<String> getPublicationReferences();

    /**
     * @return return list of publication repository URI's or empty list.
     */
    List<String> getPublicationRepositoryURIs();
}
