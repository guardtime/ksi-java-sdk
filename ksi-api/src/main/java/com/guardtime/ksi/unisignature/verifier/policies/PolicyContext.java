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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.util.Util;

public class PolicyContext {

    private PublicationsHandler publicationsHandler;
    private KSIExtendingService extendingService;
    private PublicationData userPublication;

    public PolicyContext() {}

    public PolicyContext(KSIExtendingService extendingService) {
        Util.notNull(extendingService, "Extending service");
        this.extendingService = extendingService;
    }

    public PolicyContext(PublicationsHandler publicationsHandler, KSIExtendingService extendingService) {
        Util.notNull(publicationsHandler, "Publications handler");
        this.publicationsHandler = publicationsHandler;
        this.extendingService = extendingService;
    }

    public PolicyContext(PublicationData publicationData) {
        this(publicationData, null);
    }

    public PolicyContext(PublicationData publicationData, KSIExtendingService extendingService) {
        Util.notNull(publicationData, "Publication data");
        this.userPublication = publicationData;
        this.extendingService = extendingService;
    }

    public PublicationsHandler getPublicationsHandler() {
        return publicationsHandler;
    }

    public KSIExtendingService getExtendingService() {
        return extendingService;
    }

    public boolean isExtendingAllowed() {
        return extendingService != null;
    }

    public PublicationData getUserPublication() {
        return userPublication;
    }

}
