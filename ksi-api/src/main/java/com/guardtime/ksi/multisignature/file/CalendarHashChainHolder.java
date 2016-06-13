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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.unisignature.CalendarHashChain;

import java.util.Date;

/**
 * This class is used to hold calendar hash chains in multi signature. A calendar hash chain is key is aggregation
 * time.
 */
final class CalendarHashChainHolder extends TlvStructureHolder<Date, CalendarHashChain> {

    @Override
    Date createKey(CalendarHashChain calendarHashChain) {
        return calendarHashChain.getAggregationTime();
    }

    @Override
    String getTlvElementName() {
        return "calendar hash chain";
    }

}
