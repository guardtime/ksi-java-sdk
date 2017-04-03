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

package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * ExtenderConfigurationPayload provides additional information about the Extender.
 */
public class ExtenderConfigurationPayload extends TLVStructure implements ExtenderConfiguration {

    private static final int TYPE_MAXIMUM_REQUESTS = 0x04;
    private static final int TYPE_PARENT = 0x10;
    private static final int TYPE_CALENDAR_FIRST_TIME = 0x11;
    private static final int TYPE_CALENDAR_LAST_TIME = 0x12;

    private Long maximumRequests;
    private List<String> parents = new LinkedList<String>();
    private Date calendarFirstTime;
    private Date calendarLastTime;

    public ExtenderConfigurationPayload(TLVElement element) throws TLVParserException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case TYPE_MAXIMUM_REQUESTS:
                    this.maximumRequests = readOnce(child).getDecodedLong();
                    continue;
                case TYPE_PARENT:
                    this.parents.add(child.getDecodedString());
                    continue;
                case TYPE_CALENDAR_FIRST_TIME:
                    this.calendarFirstTime = readOnce(child).getDecodedDate();
                    continue;
                case TYPE_CALENDAR_LAST_TIME:
                    this.calendarLastTime = readOnce(child).getDecodedDate();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
    }

    public Long getMaximumRequests() {
        return maximumRequests;
    }

    public List<String> getParents() {
        return parents;
    }

    public Date getCalendarFirstTime() {
        return calendarFirstTime;
    }

    public Date getCalendarLastTime() {
        return calendarLastTime;
    }

    public int getElementType() {
        return 0x04;
    }

    @Override
    public String toString() {
        return "ExtenderConfiguration{" +
                "maximumRequests=" + maximumRequests +
                ", parents=" + parents +
                ", calendarFirstTime=" + calendarFirstTime +
                ", calendarLastTime=" + calendarLastTime +
                '}';
    }

}
